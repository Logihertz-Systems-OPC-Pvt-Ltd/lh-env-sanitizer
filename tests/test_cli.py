# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""End-to-end and CLI tests using Typer CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_env_sanitizer.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "lh-env version" in result.stdout


def test_cli_audit_clean_env(tmp_path: Path) -> None:
    clean_env = tmp_path / ".env"
    clean_env.write_text("APP_NAME=my-app\nPORT=8080\n", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(clean_env)])
    assert result.exit_code == 0
    assert "No security issues or insecure flags detected" in result.stdout


def test_cli_audit_vulnerable_env(tmp_path: Path) -> None:
    bad_env = tmp_path / ".env"
    bad_env.write_text(
        "NODE_TLS_REJECT_UNAUTHORIZED=0\n"
        "DEBUG=true\n"
        "API_KEY=ghp_123456789012345678901234567890123456\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["audit", str(bad_env)])
    assert result.exit_code == 1
    assert "LH-TLS-001" in result.stdout
    assert "LH-DBG-001" in result.stdout
    assert "LH-SEC-001" in result.stdout


def test_cli_audit_directory(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("DEBUG=true\n", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(tmp_path)])
    assert result.exit_code == 1
    assert "LH-DBG-001" in result.stdout


def test_cli_audit_json_format(tmp_path: Path) -> None:
    bad_env = tmp_path / ".env"
    bad_env.write_text("DEBUG=true\n", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(bad_env), "--format", "json"])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["summary"]["total_findings"] >= 1


def test_cli_audit_sarif_output_file(tmp_path: Path) -> None:
    bad_env = tmp_path / ".env"
    bad_env.write_text("PYTHONHTTPSVERIFY=0\n", encoding="utf-8")
    out_sarif = tmp_path / "report.sarif"

    result = runner.invoke(
        app, ["audit", str(bad_env), "--format", "sarif", "--output", str(out_sarif)]
    )
    assert result.exit_code == 1
    assert out_sarif.exists()

    sarif_data = json.loads(out_sarif.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["results"][0]["ruleId"] == "LH-TLS-001"


def test_cli_audit_table_output_file(tmp_path: Path) -> None:
    bad_env = tmp_path / ".env"
    bad_env.write_text("PYTHONHTTPSVERIFY=0\n", encoding="utf-8")
    out_table = tmp_path / "report.txt"

    result = runner.invoke(
        app, ["audit", str(bad_env), "--format", "table", "--output", str(out_table)]
    )
    assert result.exit_code == 1
    assert out_table.exists()
    assert "LH-TLS-001" in out_table.read_text(encoding="utf-8")


def test_cli_audit_json_output_file(tmp_path: Path) -> None:
    bad_env = tmp_path / ".env"
    bad_env.write_text("PYTHONHTTPSVERIFY=0\n", encoding="utf-8")
    out_json = tmp_path / "report.json"

    result = runner.invoke(
        app, ["audit", str(bad_env), "--format", "json", "--output", str(out_json)]
    )
    assert result.exit_code == 1
    assert out_json.exists()


def test_cli_sanitize_command(tmp_path: Path) -> None:
    live_env = tmp_path / ".env"
    live_env.write_text(
        "DB_PASSWORD=SecretPassword123\nPORT=3000\nDEBUG=true\n",
        encoding="utf-8",
    )
    example_out = tmp_path / ".env.example"

    result = runner.invoke(app, ["sanitize", str(live_env), "--output", str(example_out)])
    assert result.exit_code == 0
    assert example_out.exists()

    content = example_out.read_text(encoding="utf-8")
    assert "SecretPassword123" not in content
    assert "your_db_password_here" in content
    assert "# (boolean)" in content


def test_cli_sanitize_stdout(tmp_path: Path) -> None:
    live_env = tmp_path / ".env"
    live_env.write_text("PORT=3000\n", encoding="utf-8")

    result = runner.invoke(app, ["sanitize", str(live_env)])
    assert result.exit_code == 0
    assert "PORT=3000 # (integer, port)" in result.stdout


def test_cli_scan_proc_mock(tmp_path: Path) -> None:
    mock_environ = tmp_path / "mock_environ"
    mock_environ.write_bytes(b"NODE_TLS_REJECT_UNAUTHORIZED=0\x00PORT=8080\x00")

    result = runner.invoke(
        app,
        ["scan-proc", "--pid", "9999", "--environ-file", str(mock_environ), "--format", "json"],
    )
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["findings"][0]["rule_id"] == "LH-TLS-001"


def test_cli_scan_proc_missing_process() -> None:
    result = runner.invoke(app, ["scan-proc", "--pid", "99999999"])
    assert result.exit_code == 2
    assert "Scan process failed" in result.stdout
