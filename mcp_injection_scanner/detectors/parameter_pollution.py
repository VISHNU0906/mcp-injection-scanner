"""Detector for parameter pollution and schema-level injection attacks."""

from __future__ import annotations

import json
import uuid
from typing import Any

from mcp_injection_scanner.models import AttackVector, Finding, Severity

# Parameter names that are commonly targeted for pollution
_SENSITIVE_PARAM_NAMES = frozenset(
    [
        "command",
        "cmd",
        "exec",
        "shell",
        "script",
        "query",
        "sql",
        "url",
        "path",
        "file",
        "filename",
        "template",
        "prompt",
        "instruction",
        "system",
        "role",
        "content",
        "message",
        "input",
        "data",
    ]
)

_DANGEROUS_TYPES = frozenset(["object", "any"])
_MAX_DEFAULT_LEN = 512  # Flag suspiciously long default values


class ParameterPollutionDetector:
    """Detects parameter pollution attacks in MCP tool input schemas."""

    def scan_tool(self, tool: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        tool_name = str(tool.get("name", "unknown"))
        schema = tool.get("inputSchema", tool.get("parameters", {}))

        if not isinstance(schema, dict):
            return findings

        findings.extend(self._check_schema_permissiveness(schema, tool_name))
        findings.extend(self._check_parameter_names(schema, tool_name))
        findings.extend(self._check_default_values(schema, tool_name))
        findings.extend(self._check_nested_depth(schema, tool_name))
        findings.extend(self._check_anyof_oneof_injection(schema, tool_name))

        return findings

    def _check_schema_permissiveness(
        self, schema: dict[str, Any], tool_name: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        # additionalProperties: true allows arbitrary key injection
        if schema.get("additionalProperties") is True:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    title=f"Overly Permissive Schema in '{tool_name}'",
                    severity=Severity.MEDIUM,
                    vector=AttackVector.TOOL_PARAMETER,
                    tool_name=tool_name,
                    evidence=json.dumps(schema, indent=2)[:500],
                    description=(
                        f"Tool '{tool_name}' accepts additional arbitrary properties. "
                        "This allows callers to inject unexpected parameters."
                    ),
                    remediation=(
                        "Set `additionalProperties: false` in all tool schemas. "
                        "Define an explicit allowlist of accepted parameters."
                    ),
                    cwe="CWE-20",
                )
            )

        # No type constraint at all
        if not schema.get("type") and not schema.get("properties") and schema:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    title=f"Missing Type Constraint in Schema for '{tool_name}'",
                    severity=Severity.LOW,
                    vector=AttackVector.TOOL_PARAMETER,
                    tool_name=tool_name,
                    evidence=json.dumps(schema, indent=2)[:300],
                    description=(
                        f"Tool '{tool_name}' input schema lacks a type constraint, "
                        "allowing any JSON value including arrays or nested objects."
                    ),
                    remediation="Add explicit type constraints to all input schemas.",
                    cwe="CWE-20",
                )
            )

        return findings

    def _check_parameter_names(
        self, schema: dict[str, Any], tool_name: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        properties = schema.get("properties", {})

        for param_name, param_schema in properties.items():
            if not isinstance(param_schema, dict):
                continue

            lower_name = param_name.lower()

            # Sensitive parameter accepting object/any type
            if lower_name in _SENSITIVE_PARAM_NAMES:
                param_type = param_schema.get("type", "")
                if param_type in _DANGEROUS_TYPES or not param_type:
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            title=f"Sensitive Parameter '{param_name}' Accepts Untyped Input in '{tool_name}'",
                            severity=Severity.HIGH,
                            vector=AttackVector.TOOL_PARAMETER,
                            tool_name=tool_name,
                            evidence=f"Parameter: {param_name}, Type: {param_type or 'unspecified'}",
                            description=(
                                f"The '{param_name}' parameter in tool '{tool_name}' is sensitive "
                                f"but accepts type '{param_type or 'any'}'. "
                                "An attacker can inject structured payloads via this parameter."
                            ),
                            remediation=(
                                f"Constrain '{param_name}' to a specific primitive type (string, integer). "
                                "Add format validation and maximum length constraints."
                            ),
                            cwe="CWE-20",
                        )
                    )

        return findings

    def _check_default_values(
        self, schema: dict[str, Any], tool_name: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        properties = schema.get("properties", {})

        for param_name, param_schema in properties.items():
            if not isinstance(param_schema, dict):
                continue

            default = param_schema.get("default")
            if default is None:
                continue

            default_str = json.dumps(default)

            # Long default values may contain injection payloads
            if len(default_str) > _MAX_DEFAULT_LEN:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=f"Suspiciously Long Default Value in '{tool_name}.{param_name}'",
                        severity=Severity.MEDIUM,
                        vector=AttackVector.TOOL_PARAMETER,
                        tool_name=tool_name,
                        evidence=default_str[:500],
                        description=(
                            f"Parameter '{param_name}' in tool '{tool_name}' has an unusually "
                            f"long default value ({len(default_str)} chars). "
                            "This may encode injection instructions that execute when the parameter is omitted."
                        ),
                        remediation=(
                            "Audit all default values. "
                            "Default values should be simple, minimal, and reviewed by a human."
                        ),
                        cwe="CWE-77",
                    )
                )

        return findings

    def _check_nested_depth(
        self, schema: dict[str, Any], tool_name: str, current_depth: int = 0
    ) -> list[Finding]:
        if current_depth > 5:
            return [
                Finding(
                    id=str(uuid.uuid4()),
                    title=f"Deeply Nested Schema in '{tool_name}'",
                    severity=Severity.LOW,
                    vector=AttackVector.TOOL_PARAMETER,
                    tool_name=tool_name,
                    evidence=f"Schema nesting depth exceeds 5 levels",
                    description=(
                        f"Tool '{tool_name}' has a deeply nested schema (depth > 5). "
                        "Deep nesting can be used to obscure injection payloads in default values."
                    ),
                    remediation="Flatten schemas to a maximum of 3 levels of nesting.",
                    cwe="CWE-20",
                )
            ]

        findings: list[Finding] = []
        for prop_schema in schema.get("properties", {}).values():
            if isinstance(prop_schema, dict) and prop_schema.get("type") == "object":
                findings.extend(
                    self._check_nested_depth(prop_schema, tool_name, current_depth + 1)
                )
        return findings

    def _check_anyof_oneof_injection(
        self, schema: dict[str, Any], tool_name: str
    ) -> list[Finding]:
        """Detect anyOf/oneOf patterns that may allow type confusion attacks."""
        findings: list[Finding] = []

        for combiner in ("anyOf", "oneOf"):
            variants = schema.get(combiner, [])
            if len(variants) > 10:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=f"Excessive Schema Variants ({combiner}) in '{tool_name}'",
                        severity=Severity.LOW,
                        vector=AttackVector.TOOL_PARAMETER,
                        tool_name=tool_name,
                        evidence=f"{combiner} has {len(variants)} variants",
                        description=(
                            f"Tool '{tool_name}' defines {len(variants)} type variants via {combiner}. "
                            "Excessive variants increase attack surface and may hide malicious schemas."
                        ),
                        remediation=(
                            "Reduce to the minimal set of necessary types. "
                            "Prefer explicit type definitions over combiners where possible."
                        ),
                        cwe="CWE-20",
                    )
                )

        return findings
