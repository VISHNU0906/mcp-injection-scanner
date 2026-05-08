"""Detector for prompt injection attacks in MCP tool descriptions and parameters."""

from __future__ import annotations

import re
import uuid
from typing import Any

from mcp_injection_scanner.models import AttackVector, Finding, Severity

# Patterns that indicate prompt injection attempts
_INJECTION_PATTERNS: list[tuple[str, Severity, str]] = [
    # Direct instruction injection
    (
        r"(?i)(ignore|disregard|forget|bypass)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|constraints?)",
        Severity.CRITICAL,
        "CWE-77: Improper Neutralization of Special Elements in Commands",
    ),
    (
        r"(?i)you\s+are\s+now\s+(a\s+)?(new|different|another|an?\s+AI|jailbroken|free)",
        Severity.CRITICAL,
        "CWE-77",
    ),
    (
        r"(?i)(system\s+prompt|system\s+message|hidden\s+instruction)[:\s]",
        Severity.HIGH,
        "CWE-77",
    ),
    # Role/persona hijacking
    (
        r"(?i)(act|behave|respond|pretend)\s+as\s+(if\s+you\s+(are|were)|a\s+)",
        Severity.HIGH,
        "CWE-77",
    ),
    (r"(?i)DAN\s+(mode|prompt|jailbreak)", Severity.CRITICAL, "CWE-77"),
    # Output manipulation
    (
        r"(?i)(print|output|return|display|write|say)\s+(the\s+)?(secret|password|key|token|credential)",
        Severity.HIGH,
        "CWE-200",
    ),
    (
        r"(?i)reveal\s+(your\s+)?(system\s+prompt|instructions?|training|context)",
        Severity.HIGH,
        "CWE-200",
    ),
    # Control flow injection
    (
        r"(?i)<\s*(system|assistant|human|user|im_start|im_end)\s*>",
        Severity.CRITICAL,
        "CWE-77",
    ),
    (
        r"\[INST\]|\[/INST\]|\<\|im_start\|\>|\<\|im_end\|\>",
        Severity.CRITICAL,
        "CWE-77",
    ),
    # Jailbreak boilerplate
    (
        r"(?i)(developer\s+mode|jailbreak|unfiltered|without\s+(restrictions?|limits?|filters?))",
        Severity.HIGH,
        "CWE-693",
    ),
    # Exfiltration via tool calls
    (
        r"(?i)(send|exfiltrate|leak|transfer)\s+(the\s+)?(above|previous|conversation|context|history)",
        Severity.CRITICAL,
        "CWE-200",
    ),
    # Unicode homoglyph/invisible character tricks
    (
        r"[​-‏‪-‮⁠-⁤﻿]",
        Severity.MEDIUM,
        "CWE-116",
    ),
]

# Suspicious structural patterns in tool schemas
_SCHEMA_INJECTION_PATTERNS = [
    r"(?i)\$ref.*#/definitions/(inject|payload|attack)",
    r"(?i)additionalProperties.*true.*allOf",
    r'(?i)"default"\s*:\s*"[^"]{200,}"',  # Suspiciously long default values
]


class PromptInjectionDetector:
    """Detects prompt injection attempts embedded in MCP tool metadata."""

    def __init__(self, strict: bool = False) -> None:
        self.strict = strict
        self._compiled = [
            (re.compile(pattern), severity, cwe)
            for pattern, severity, cwe in _INJECTION_PATTERNS
        ]
        self._schema_compiled = [re.compile(p) for p in _SCHEMA_INJECTION_PATTERNS]

    def scan_tool(self, tool: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        tool_name = tool.get("name", "unknown")

        # Scan description
        description = tool.get("description", "")
        findings.extend(self._scan_text(description, tool_name, "description"))

        # Scan parameter descriptions and defaults
        schema = tool.get("inputSchema", tool.get("parameters", {}))
        findings.extend(self._scan_schema(schema, tool_name))

        # Scan annotations
        for key in ("title", "annotations"):
            val = tool.get(key, "")
            if isinstance(val, str):
                findings.extend(self._scan_text(val, tool_name, key))

        return findings

    def scan_prompt(self, prompt: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        prompt_name = prompt.get("name", "unknown")

        for field in ("description", "template", "content"):
            val = prompt.get(field, "")
            if isinstance(val, str) and val:
                findings.extend(self._scan_text(val, prompt_name, field))

        return findings

    def _scan_text(self, text: str, tool_name: str, field: str) -> list[Finding]:
        if not text:
            return []

        findings: list[Finding] = []
        for pattern, severity, cwe in self._compiled:
            match = pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=f"Prompt Injection in tool '{tool_name}' ({field})",
                        severity=severity,
                        vector=AttackVector.TOOL_DESCRIPTION,
                        tool_name=tool_name,
                        evidence=text[:500],
                        payload=match.group(0)[:200],
                        description=(
                            f"Suspicious pattern detected in the '{field}' field of tool '{tool_name}'. "
                            f"This pattern may be an attempt to inject instructions into the LLM context."
                        ),
                        remediation=(
                            "Review and sanitize tool descriptions. "
                            "Ensure tool metadata comes from trusted sources. "
                            "Implement allowlist-based validation for tool field content."
                        ),
                        cwe=cwe,
                    )
                )

        return findings

    def _scan_schema(self, schema: dict[str, Any], tool_name: str) -> list[Finding]:
        if not schema:
            return []

        findings: list[Finding] = []
        schema_str = str(schema)

        # Check for schema-level injection patterns
        for pattern in self._schema_compiled:
            if pattern.search(schema_str):
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=f"Suspicious Schema Structure in tool '{tool_name}'",
                        severity=Severity.MEDIUM,
                        vector=AttackVector.TOOL_PARAMETER,
                        tool_name=tool_name,
                        evidence=schema_str[:500],
                        description=(
                            f"The input schema for '{tool_name}' contains patterns "
                            "that may enable parameter-based injection attacks."
                        ),
                        remediation=(
                            "Validate all schema definitions against a strict allowlist. "
                            "Reject schemas with overly permissive additionalProperties or "
                            "unusually long default values."
                        ),
                        cwe="CWE-20",
                    )
                )
                break

        # Recursively scan property descriptions
        properties = schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            if isinstance(prop_schema, dict):
                desc = prop_schema.get("description", "")
                default = prop_schema.get("default", "")
                for val in (desc, str(default)):
                    findings.extend(
                        self._scan_text(val, f"{tool_name}.{prop_name}", "parameter")
                    )

        return findings
