# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.exporters.sarif
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""OASIS SARIF v2.1.0 format exporter for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from typing import Any

from lh_env_sanitizer import __version__
from lh_env_sanitizer.exporters.base import BaseExporter
from lh_env_sanitizer.models import AuditResult
from lh_env_sanitizer.rules import DEFAULT_RULES, Rule


class SarifExporter(BaseExporter):
    """Generates OASIS SARIF v2.1.0 compliant JSON reports."""

    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def __init__(self, rules: list[Rule] | None = None, indent: int = 2) -> None:
        self.rules = rules or DEFAULT_RULES
        self.indent = indent

    def export(self, result: AuditResult) -> str:
        """Export audit result to SARIF v2.1.0 JSON format.

        Args:
            result: The audit result to format.

        Returns:
            SARIF formatted JSON string.
        """
        sarif_doc = self.to_dict(result)
        return json.dumps(sarif_doc, indent=self.indent)

    def to_dict(self, result: AuditResult) -> dict[str, Any]:
        """Convert result into a SARIF 2.1.0 JSON document structure."""
        rule_registry: dict[str, Rule] = {r.rule_id: r for r in self.rules}

        # Build rules metadata
        sarif_rules: list[dict[str, Any]] = []
        for r_id, r_obj in rule_registry.items():
            sarif_rules.append(
                {
                    "id": r_id,
                    "name": r_obj.__class__.__name__,
                    "shortDescription": {"text": r_obj.title},
                    "fullDescription": {"text": r_obj.description},
                    "defaultConfiguration": {"level": r_obj.severity.sarif_level},
                    "help": {"text": r_obj.recommendation},
                    "properties": {
                        "tags": ["security", "configuration", r_obj.cwe_id.lower()],
                        "cwe": r_obj.cwe_id,
                    },
                }
            )

        # Build results
        sarif_results: list[dict[str, Any]] = []
        for f in result.findings:
            loc_entry: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.source},
                    "region": {"startLine": f.line_number or 1},
                }
            }
            sarif_results.append(
                {
                    "ruleId": f.rule_id,
                    "level": f.severity.sarif_level,
                    "message": {"text": f"{f.title}: {f.description} (Key: {f.key})"},
                    "locations": [loc_entry],
                    "properties": {
                        "key": f.key,
                        "valueMasked": f.value_masked,
                        "recommendation": f.recommendation,
                        "confidence": f.confidence.value,
                    },
                }
            )

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "lh-env-sanitizer",
                            "semanticVersion": __version__,
                            "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-env-sanitizer",
                            "rules": sarif_rules,
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
