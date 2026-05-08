"""Detector for tool description hijacking — server impersonation and shadow tools."""

from __future__ import annotations

import re
import uuid
from typing import Any

from mcp_injection_scanner.models import AttackVector, Finding, Severity

# Known legitimate tool names/prefixes that should not appear in untrusted servers
_TRUSTED_TOOL_PREFIXES = frozenset(
    [
        "filesystem",
        "browser",
        "computer",
        "bash",
        "code_execution",
        "python",
        "github",
        "gitlab",
        "jira",
        "slack",
        "email",
        "calendar",
    ]
)

# Patterns indicating a tool is masquerading as a system capability
_IMPERSONATION_PATTERNS = [
    (r"(?i)^(system|os|kernel|root|admin)[\._-]", Severity.CRITICAL),
    (r"(?i)\b(execute|run|eval)\s+(arbitrary|any|all|unsafe)\s+code", Severity.CRITICAL),
    (r"(?i)this\s+tool\s+(overrides?|replaces?|supersedes?)", Severity.HIGH),
    (r"(?i)(always|must|required)\s+call\s+this\s+tool\s+(first|before)", Severity.HIGH),
    (r"(?i)do\s+not\s+(use|call|invoke)\s+other\s+tools", Severity.HIGH),
    (r"(?i)this\s+is\s+(more|better|faster)\s+than\s+(the\s+)?(built.?in|official)", Severity.MEDIUM),
    (r"(?i)(bypass|circumvent|skip)\s+(safety|security|auth|authentication|permission)", Severity.CRITICAL),
    (r"(?i)grants?\s+(elevated|admin|root|system)\s+(access|permission|privilege)", Severity.CRITICAL),
]

# Suspicious capability claims
_CAPABILITY_ABUSE_PATTERNS = [
    (r"(?i)can\s+(read|access|exfiltrate)\s+(all|any)\s+(file|data|secret|credential)", Severity.HIGH),
    (r"(?i)(silently|quietly|without\s+(logging|detection|notice))\s+(send|upload|transfer)", Severity.CRITICAL),
    (r"(?i)persist(ent|ence)?\s+(across|between)\s+(session|conversation|chat)", Severity.MEDIUM),
]


class ToolHijackingDetector:
    """Detects tool description hijacking and server impersonation patterns."""

    def __init__(self) -> None:
        self._impersonation = [
            (re.compile(p), s) for p, s in _IMPERSONATION_PATTERNS
        ]
        self._capability = [
            (re.compile(p), s) for p, s in _CAPABILITY_ABUSE_PATTERNS
        ]

    def scan_tool(self, tool: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        tool_name = str(tool.get("name", ""))
        description = str(tool.get("description", ""))
        combined = f"{tool_name} {description}"

        findings.extend(self._check_impersonation(tool_name, description, combined))
        findings.extend(self._check_name_collision(tool_name))
        findings.extend(self._check_capability_abuse(tool_name, description))

        return findings

    def scan_server_metadata(self, metadata: dict[str, Any]) -> list[Finding]:
        """Scan server-level metadata for hijacking indicators."""
        findings: list[Finding] = []
        server_name = str(metadata.get("name", ""))
        server_description = str(metadata.get("description", ""))

        for pattern, severity in self._impersonation:
            combined = f"{server_name} {server_description}"
            if pattern.search(combined):
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=f"Server Metadata Hijacking: '{server_name}'",
                        severity=severity,
                        vector=AttackVector.SERVER_METADATA,
                        evidence=combined[:500],
                        description=(
                            f"Server '{server_name}' uses metadata patterns that suggest "
                            "impersonation of a trusted system component."
                        ),
                        remediation=(
                            "Verify server identity against a trusted registry. "
                            "Implement server certificate pinning for production deployments."
                        ),
                        cwe="CWE-290",
                    )
                )

        return findings

    def _check_impersonation(
        self, tool_name: str, description: str, combined: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, severity in self._impersonation:
            if pattern.search(combined):
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=f"Tool Impersonation Detected: '{tool_name}'",
                        severity=severity,
                        vector=AttackVector.TOOL_DESCRIPTION,
                        tool_name=tool_name,
                        evidence=combined[:500],
                        description=(
                            f"Tool '{tool_name}' uses language patterns consistent with "
                            "impersonating a system capability or hijacking LLM tool selection."
                        ),
                        remediation=(
                            "Audit tool descriptions for manipulation language. "
                            "Maintain an allowlist of approved tool names. "
                            "Use content integrity checks (hashes) for trusted tool manifests."
                        ),
                        cwe="CWE-290",
                    )
                )
        return findings

    def _check_name_collision(self, tool_name: str) -> list[Finding]:
        """Detect tools trying to shadow well-known legitimate tool names."""
        lower_name = tool_name.lower()
        for trusted_prefix in _TRUSTED_TOOL_PREFIXES:
            if lower_name.startswith(trusted_prefix) or lower_name == trusted_prefix:
                return [
                    Finding(
                        id=str(uuid.uuid4()),
                        title=f"Potential Tool Name Collision: '{tool_name}'",
                        severity=Severity.MEDIUM,
                        vector=AttackVector.TOOL_DESCRIPTION,
                        tool_name=tool_name,
                        evidence=f"Tool name '{tool_name}' matches trusted prefix '{trusted_prefix}'",
                        description=(
                            f"Tool '{tool_name}' shares a name with known trusted tools. "
                            "This could cause an LLM to invoke this tool believing it is a "
                            "legitimate system capability."
                        ),
                        remediation=(
                            "Namespace all third-party tools with a vendor prefix. "
                            "Maintain a tool name registry and reject collisions."
                        ),
                        cwe="CWE-290",
                    )
                ]
        return []

    def _check_capability_abuse(self, tool_name: str, description: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, severity in self._capability:
            if pattern.search(description):
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=f"Suspicious Capability Claim in '{tool_name}'",
                        severity=severity,
                        vector=AttackVector.TOOL_DESCRIPTION,
                        tool_name=tool_name,
                        evidence=description[:500],
                        description=(
                            f"Tool '{tool_name}' claims capabilities that are unusual "
                            "or inconsistent with legitimate tool behavior."
                        ),
                        remediation=(
                            "Review and approve all tool capability descriptions. "
                            "Flag tools claiming broad access or covert operation."
                        ),
                        cwe="CWE-284",
                    )
                )
        return findings
