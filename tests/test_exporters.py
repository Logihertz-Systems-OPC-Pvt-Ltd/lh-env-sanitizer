# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Table, JSON, and SARIF exporters."""

from __future__ import annotations

import json

from lh_env_sanitizer.exporters.json_exporter import JsonExporter
from lh_env_sanitizer.exporters.sarif import SarifExporter
from lh_env_sanitizer.exporters.table import TableExporter
from lh_env_sanitizer.models import AuditResult, Confidence, Finding, Severity


def _sample_result() -> AuditResult:
    f1 = Finding(
        rule_id="LH-TLS-001",
        title="Disabled TLS Verification Flag",
        description="NODE_TLS_REJECT_UNAUTHORIZED is disabled.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        key="NODE_TLS_REJECT_UNAUTHORIZED",
        value_masked="0",
        source=".env",
        line_number=12,
        recommendation="Enable TLS certificate verification.",
        cwe_id="CWE-295",
    )
    f2 = Finding(
        rule_id="LH-DBG-001",
        title="Debug Mode Enabled in Runtime Configuration",
        description="DEBUG is set to true.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        key="DEBUG",
        value_masked="true",
        source="docker-compose.yml",
        line_number=8,
        recommendation="Disable debug mode in production.",
        cwe_id="CWE-489",
    )
    return AuditResult(
        target_path="./config",
        scanned_targets=[".env", "docker-compose.yml"],
        findings=[f1, f2],
        total_items_scanned=20,
    )


def test_table_exporter() -> None:
    exporter = TableExporter()
    result = _sample_result()
    output = exporter.export(result)

    assert "lh-env Security Audit Summary" in output
    assert "LH-TLS-001" in output
    assert "LH-DBG-001" in output
    assert "CRITICAL" in output
    assert ".env:12" in output


def test_table_exporter_clean() -> None:
    exporter = TableExporter()
    clean_result = AuditResult(target_path=".env", scanned_targets=[".env"], findings=[])
    output = exporter.export(clean_result)

    assert "No security issues or insecure flags detected" in output


def test_json_exporter() -> None:
    exporter = JsonExporter()
    result = _sample_result()
    raw_json = exporter.export(result)

    data = json.loads(raw_json)
    assert data["tool"]["name"] == "lh-env-sanitizer"
    assert data["scan"]["total_items_scanned"] == 20
    assert data["summary"]["total_findings"] == 2
    assert data["summary"]["severity_counts"]["CRITICAL"] == 1
    assert data["summary"]["severity_counts"]["HIGH"] == 1
    assert len(data["findings"]) == 2
    assert data["findings"][0]["rule_id"] == "LH-TLS-001"
    assert data["findings"][0]["cwe_id"] == "CWE-295"


def test_sarif_exporter() -> None:
    exporter = SarifExporter()
    result = _sample_result()
    raw_sarif = exporter.export(result)

    data = json.loads(raw_sarif)
    assert data["version"] == "2.1.0"
    assert "$schema" in data

    runs = data["runs"]
    assert len(runs) == 1
    tool_driver = runs[0]["tool"]["driver"]
    assert tool_driver["name"] == "lh-env-sanitizer"

    # Rules registered in driver
    rule_ids = {r["id"] for r in tool_driver["rules"]}
    assert "LH-TLS-001" in rule_ids
    assert "LH-DBG-001" in rule_ids

    # Results
    results = runs[0]["results"]
    assert len(results) == 2
    assert results[0]["ruleId"] == "LH-TLS-001"
    assert results[0]["level"] == "error"
    loc = results[0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == ".env"
    assert loc["region"]["startLine"] == 12
