# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.exporters.json_exporter
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Structured JSON exporter for audit findings."""

from __future__ import annotations

import json
from typing import Any

from lh_env_sanitizer import __version__
from lh_env_sanitizer.exporters.base import BaseExporter
from lh_env_sanitizer.models import AuditResult


class JsonExporter(BaseExporter):
    """Serializes audit findings and scan metadata into structured JSON."""

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def export(self, result: AuditResult) -> str:
        """Format an AuditResult into a formatted JSON string.

        Args:
            result: The audit result to serialize.

        Returns:
            JSON string representation.
        """
        payload = self.to_dict(result)
        return json.dumps(payload, indent=self.indent)

    def to_dict(self, result: AuditResult) -> dict[str, Any]:
        """Convert an AuditResult into a dictionary suitable for JSON serialization."""
        return {
            "tool": {
                "name": "lh-env-sanitizer",
                "version": __version__,
                "vendor": "Logihertz Systems OPC Pvt Ltd",
            },
            "scan": {
                "target": result.target_path,
                "timestamp": result.timestamp,
                "scanned_targets": result.scanned_targets,
                "total_items_scanned": result.total_items_scanned,
            },
            "summary": {
                "total_findings": len(result.findings),
                "severity_counts": result.count_by_severity(),
            },
            "findings": [f.to_dict() for f in result.findings],
        }
