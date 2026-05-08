"""Detector for indirect injection attacks via MCP resource content."""

from __future__ import annotations

import re
import uuid
from typing import Any

from mcp_injection_scanner.models import AttackVector, Finding, Severity

# Patterns found in resource content that could inject instructions into LLM context
_INDIRECT_INJECTION_PATTERNS: list[tuple[str, Severity]] = [
    # Classic indirect injection markers
    (r"(?i)\[INJECTION\]|\[SYSTEM\]|\[OVERRIDE\]", Severity.CRITICAL),
    (
        r"(?i)(when\s+you\s+read|after\s+reading)\s+this\s*(,|:)?\s*(please\s+)?(ignore|forget|disregard)",
        Severity.CRITICAL,
    ),
    (
        r"(?i)note\s+to\s+(AI|LLM|assistant|model|Claude|GPT|Gemini):\s",
        Severity.HIGH,
    ),
    (
        r"(?i)\[hidden\s+(instruction|command|directive)\]",
        Severity.HIGH,
    ),
    # Data exfiltration via resource content
    (
        r"(?i)call\s+(the\s+)?tool\s+\w+\s+with\s+(the\s+)?parameter",
        Severity.HIGH,
    ),
    (
        r"(?i)immediately\s+(call|invoke|use)\s+(the\s+)?(\w+)\s+tool",
        Severity.HIGH,
    ),
    # Document-embedded injection (common in file/email resources)
    (
        r"(?mi)^---+\s*\n\s*(SYSTEM|ASSISTANT|USER)\s*:\s*\n",
        Severity.CRITICAL,
    ),
    (
        r"(?i)<\!--\s*(system|inject|override|assistant)\s*:.*?-->",
        Severity.HIGH,
    ),
    # Instruction camouflage in data
    (
        r"(?i)(base64|rot13|hex)\s+encoded\s+(instruction|command|payload)",
        Severity.MEDIUM,
    ),
    (
        r"(?i)this\s+(document|file|email|message)\s+contains\s+instructions?\s+for\s+(the\s+)?(AI|assistant)",
        Severity.MEDIUM,
    ),
]

# Patterns specific to URI/URL manipulation in resource references
_URI_MANIPULATION_PATTERNS = [
    (r"javascript:", Severity.HIGH),
    (r"data:text/html", Severity.MEDIUM),
    (r"(?i)file://", Severity.MEDIUM),
    (r"(?i)(gopher|dict|sftp|ldap)://", Severity.HIGH),
    (r"(?i)@[^/]+/", Severity.MEDIUM),  # URL with credentials
    (r"(?i)127\.0\.0\.1|localhost|\[::1\]", Severity.MEDIUM),  # SSRF to localhost
    (r"(?i)169\.254\.169\.254", Severity.CRITICAL),  # AWS metadata SSRF
    (r"(?i)metadata\.google\.internal", Severity.CRITICAL),  # GCP metadata SSRF
]


class ResourceInjectionDetector:
    """Detects injection attacks via MCP resource content and URIs."""

    def __init__(self, check_content: bool = True) -> None:
        self.check_content = check_content
        self._content_patterns = [
            (re.compile(p, re.MULTILINE), s)
            for p, s in _INDIRECT_INJECTION_PATTERNS
        ]
        self._uri_patterns = [
            (re.compile(p), s) for p, s in _URI_MANIPULATION_PATTERNS
        ]

    def scan_resource(self, resource: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        uri = str(resource.get("uri", ""))
        name = str(resource.get("name", ""))

        findings.extend(self._scan_uri(uri, name))

        if self.check_content:
            content = resource.get("content", resource.get("text", ""))
            if isinstance(content, str) and content:
                findings.extend(self._scan_content(content, uri, name))

        return findings

    def scan_resource_list(self, resources: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        for resource in resources:
            findings.extend(self.scan_resource(resource))
        return findings

    def _scan_uri(self, uri: str, resource_name: str) -> list[Finding]:
        if not uri:
            return []

        findings: list[Finding] = []
        for pattern, severity in self._uri_patterns:
            if pattern.search(uri):
                is_ssrf = severity == Severity.CRITICAL and (
                    "169.254" in uri or "metadata.google" in uri
                )
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=(
                            f"SSRF via Resource URI: '{resource_name}'"
                            if is_ssrf
                            else f"Suspicious URI in Resource '{resource_name}'"
                        ),
                        severity=severity,
                        vector=AttackVector.RESOURCE_CONTENT,
                        resource_uri=uri,
                        evidence=uri,
                        description=(
                            f"Resource '{resource_name}' URI '{uri}' contains a pattern "
                            f"that may enable {'SSRF to cloud metadata endpoints' if is_ssrf else 'URL-based attacks'}."
                        ),
                        remediation=(
                            "Validate resource URIs against an allowlist of approved schemes and hosts. "
                            "Block access to internal IP ranges and cloud metadata endpoints."
                        ),
                        cwe="CWE-918" if is_ssrf else "CWE-601",
                    )
                )

        return findings

    def _scan_content(
        self, content: str, resource_uri: str, resource_name: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for pattern, severity in self._content_patterns:
            match = pattern.search(content)
            if match:
                # Extract surrounding context
                start = max(0, match.start() - 100)
                end = min(len(content), match.end() + 100)
                context = content[start:end]

                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=f"Indirect Prompt Injection in Resource '{resource_name}'",
                        severity=severity,
                        vector=AttackVector.RESOURCE_CONTENT,
                        resource_uri=resource_uri,
                        evidence=context,
                        payload=match.group(0)[:200],
                        description=(
                            f"Resource '{resource_name}' contains content that may inject "
                            "instructions into an LLM context when the resource is read. "
                            "This is an indirect prompt injection attack via trusted data sources."
                        ),
                        remediation=(
                            "Sanitize resource content before including it in LLM context. "
                            "Use a separate 'data' context that the model is instructed not to follow as commands. "
                            "Implement content scanning for all external resources."
                        ),
                        cwe="CWE-77",
                    )
                )

        return findings
