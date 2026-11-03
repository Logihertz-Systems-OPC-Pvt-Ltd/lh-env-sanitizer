# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Domain models and data structures for lh-env-sanitizer.

Defines findings, severities, confidence ratings, and parsed environment items
used across parsers, rules, and exporters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity ratings for security and configuration findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def level_rank(self) -> int:
        """Numeric rank for sorting and comparison (higher is more severe)."""
        ranks = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5,
        }
        return ranks.get(self, 0)

    @property
    def sarif_level(self) -> str:
        """Map severity to OASIS SARIF v2.1.0 notification level."""
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"


class Confidence(str, Enum):
    """Confidence levels for detection accuracy."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class OutputFormat(str, Enum):
    """Supported output formats for reporting findings."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class SourceType(str, Enum):
    """Types of configuration sources inspected by the auditor."""

    DOTENV = "dotenv"
    DOCKER_COMPOSE = "docker-compose"
    K8S_CONFIGMAP = "k8s-configmap"
    YAML = "yaml"
    PROC_ENVIRON = "proc-environ"


@dataclass(frozen=True)
class EnvItem:
    """Represents a single configuration key-value item from a parsed source."""

    key: str
    value: str
    source: str
    source_type: SourceType
    line_number: int | None = None
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    """A detected security vulnerability, insecure flag, or schema anomaly."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    key: str
    value_masked: str
    source: str
    line_number: int | None
    recommendation: str
    cwe_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert finding into a serializable dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "key": self.key,
            "value_masked": self.value_masked,
            "source": self.source,
            "line_number": self.line_number,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
        }


@dataclass
class AuditResult:
    """Aggregated results from an audit run over one or more targets."""

    target_path: str
    scanned_targets: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    total_items_scanned: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def count_by_severity(self) -> dict[str, int]:
        """Return counts of findings grouped by severity level."""
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def has_failures(self, fail_on: Severity = Severity.MEDIUM) -> bool:
        """Check if any finding meets or exceeds the specified severity threshold."""
        threshold = fail_on.level_rank
        return any(f.severity.level_rank >= threshold for f in self.findings)
