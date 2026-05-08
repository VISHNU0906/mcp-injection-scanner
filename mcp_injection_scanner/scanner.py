"""Core MCP scanner — connects to a server and runs all detectors."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin

import httpx

from mcp_injection_scanner.detectors import (
    ParameterPollutionDetector,
    PromptInjectionDetector,
    ResourceInjectionDetector,
    ToolHijackingDetector,
)
from mcp_injection_scanner.models import Finding, ScanResult, Severity


class MCPScanner:
    """
    Connects to an MCP server over HTTP/SSE and runs all injection detectors.

    Supports both the standard MCP HTTP transport and direct JSON fixture scanning
    for offline analysis of exported server manifests.
    """

    def __init__(
        self,
        timeout: float = 30.0,
        check_resources: bool = True,
        strict: bool = False,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self.check_resources = check_resources
        self.strict = strict
        self._headers = headers or {}

        self._injection = PromptInjectionDetector(strict=strict)
        self._hijacking = ToolHijackingDetector()
        self._pollution = ParameterPollutionDetector()
        self._resource = ResourceInjectionDetector(check_content=check_resources)

    def scan_url(self, server_url: str) -> ScanResult:
        """Connect to a live MCP server and scan it."""
        start = time.monotonic()

        with httpx.Client(timeout=self.timeout, headers=self._headers) as client:
            manifest = self._fetch_manifest(client, server_url)

        result = self._run_detectors(server_url, manifest)
        result.scan_duration_ms = (time.monotonic() - start) * 1000
        return result

    def scan_manifest(self, server_url: str, manifest: dict[str, Any]) -> ScanResult:
        """Scan a pre-loaded manifest dict (offline mode)."""
        start = time.monotonic()
        result = self._run_detectors(server_url, manifest)
        result.scan_duration_ms = (time.monotonic() - start) * 1000
        return result

    def _fetch_manifest(self, client: httpx.Client, server_url: str) -> dict[str, Any]:
        """Fetch the server manifest via the MCP protocol."""
        manifest: dict[str, Any] = {}

        # Try standard MCP initialize endpoint
        for path in ("/", "/mcp", "/api"):
            try:
                resp = client.post(
                    urljoin(server_url, path),
                    json={
                        "jsonrpc": "2.0",
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "clientInfo": {"name": "mcp-injection-scanner", "version": "0.3.1"},
                            "capabilities": {},
                        },
                        "id": 1,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if "result" in data:
                        manifest["serverInfo"] = data["result"].get("serverInfo", {})
                        manifest["capabilities"] = data["result"].get("capabilities", {})
                    break
            except (httpx.ConnectError, httpx.TimeoutException):
                continue

        # Fetch tools list
        try:
            resp = client.post(
                urljoin(server_url, "/"),
                json={"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 2},
            )
            if resp.status_code == 200:
                data = resp.json()
                manifest["tools"] = data.get("result", {}).get("tools", [])
        except (httpx.ConnectError, httpx.TimeoutException, KeyError):
            manifest["tools"] = []

        # Fetch resources list
        if self.check_resources:
            try:
                resp = client.post(
                    urljoin(server_url, "/"),
                    json={"jsonrpc": "2.0", "method": "resources/list", "params": {}, "id": 3},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    manifest["resources"] = data.get("result", {}).get("resources", [])
            except (httpx.ConnectError, httpx.TimeoutException, KeyError):
                manifest["resources"] = []

        # Fetch prompts list
        try:
            resp = client.post(
                urljoin(server_url, "/"),
                json={"jsonrpc": "2.0", "method": "prompts/list", "params": {}, "id": 4},
            )
            if resp.status_code == 200:
                data = resp.json()
                manifest["prompts"] = data.get("result", {}).get("prompts", [])
        except (httpx.ConnectError, httpx.TimeoutException, KeyError):
            manifest["prompts"] = []

        return manifest

    def _run_detectors(self, server_url: str, manifest: dict[str, Any]) -> ScanResult:
        server_info = manifest.get("serverInfo", {})
        tools = manifest.get("tools", [])
        resources = manifest.get("resources", [])
        prompts = manifest.get("prompts", [])

        all_findings: list[Finding] = []

        # Server metadata check
        all_findings.extend(self._hijacking.scan_server_metadata(server_info))

        # Tool scans
        for tool in tools:
            all_findings.extend(self._injection.scan_tool(tool))
            all_findings.extend(self._hijacking.scan_tool(tool))
            all_findings.extend(self._pollution.scan_tool(tool))

        # Resource scans
        for resource in resources:
            all_findings.extend(self._resource.scan_resource(resource))

        # Prompt scans
        for prompt in prompts:
            all_findings.extend(self._injection.scan_prompt(prompt))

        # De-duplicate by (title, tool_name, evidence[:100])
        seen: set[tuple[str, str | None, str]] = set()
        unique_findings: list[Finding] = []
        for f in all_findings:
            key = (f.title, f.tool_name, f.evidence[:100])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Sort: critical first
        severity_order = {s: i for i, s in enumerate(Severity)}
        unique_findings.sort(key=lambda f: severity_order[f.severity])

        return ScanResult(
            server_url=server_url,
            server_name=server_info.get("name"),
            server_version=server_info.get("version"),
            findings=unique_findings,
            tools_scanned=len(tools),
            resources_scanned=len(resources),
            prompts_scanned=len(prompts),
            metadata={
                "capabilities": manifest.get("capabilities", {}),
                "strict_mode": self.strict,
            },
        )
