"""Data models for scan results and findings."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackVector(str, Enum):
    TOOL_DESCRIPTION = "tool_description"
    TOOL_PARAMETER = "tool_parameter"
    RESOURCE_CONTENT = "resource_content"
    SERVER_METADATA = "server_metadata"
    PROMPT_TEMPLATE = "prompt_template"


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    vector: AttackVector
    tool_name: str | None = None
    resource_uri: str | None = None
    evidence: str
    payload: str | None = None
    description: str
    remediation: str
    cwe: str | None = None
    cvss_score: float | None = None

    @property
    def is_critical_or_high(self) -> bool:
        return self.severity in (Severity.CRITICAL, Severity.HIGH)


class ScanResult(BaseModel):
    server_url: str
    server_name: str | None = None
    server_version: str | None = None
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    findings: list[Finding] = Field(default_factory=list)
    tools_scanned: int = 0
    resources_scanned: int = 0
    prompts_scanned: int = 0
    scan_duration_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def passed(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0

    def by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for finding in self.findings:
            result[finding.severity].append(finding)
        return result
