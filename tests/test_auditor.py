# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        tests.test_auditor
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the EnvironmentAuditor coordinator class."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from lh_env_sanitizer.auditor import EnvironmentAuditor
from lh_env_sanitizer.models import Severity


def test_audit_directory_discovery(tmp_path: Path) -> None:
    # Set up test project directory structure
    env_file = tmp_path / ".env"
    env_file.write_text("DEBUG=true\n", encoding="utf-8")

    env_prod = tmp_path / ".env.production"
    env_prod.write_text("NODE_TLS_REJECT_UNAUTHORIZED=0\n", encoding="utf-8")

    compose_file = tmp_path / "docker-compose.yml"
    compose_content = (
        "services:\n"
        "  app:\n"
        "    environment:\n"
        "      - API_KEY=ghp_123456789012345678901234567890123456\n"
    )
    compose_file.write_text(compose_content, encoding="utf-8")

    # Ignored files
    ignored_example = tmp_path / ".env.example"
    ignored_example.write_text("DEBUG=false\n", encoding="utf-8")

    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / ".env").write_text("SECRET=leaked_in_git\n", encoding="utf-8")

    auditor = EnvironmentAuditor()
    result = auditor.audit_path(tmp_path)

    assert result.total_items_scanned >= 3
    assert len(result.findings) >= 3
    assert result.has_failures(Severity.HIGH)

    # Ensure .env.example was not audited
    for scanned in result.scanned_targets:
        assert ".env.example" not in scanned
        assert ".git" not in scanned


def test_audit_non_existent_path(tmp_path: Path) -> None:
    auditor = EnvironmentAuditor()
    with pytest.raises(FileNotFoundError, match="Target path does not exist"):
        auditor.audit_path(tmp_path / "non_existent")


def test_audit_current_proc() -> None:
    current_pid = os.getpid()
    auditor = EnvironmentAuditor()
    result = auditor.audit_proc(current_pid)

    assert result.target_path == f"/proc/{current_pid}/environ"
    assert result.total_items_scanned > 0
