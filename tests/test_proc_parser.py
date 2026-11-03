# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        tests.test_proc_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Linux /proc/<pid>/environ parser and mock environments."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from lh_env_sanitizer.models import SourceType
from lh_env_sanitizer.parsers.proc_parser import ProcEnvironError, ProcParser


def test_parse_null_terminated_bytes() -> None:
    raw_environ = (
        b"PATH=/usr/bin:/bin\x00"
        b"USER=appuser\x00"
        b"NODE_TLS_REJECT_UNAUTHORIZED=0\x00"
        b"DB_PASSWORD=SuperSecretPass123\x00"
    )
    parser = ProcParser()
    items = parser.parse_bytes(raw_environ, "/proc/1234/environ")

    assert len(items) == 4
    assert items[0].key == "PATH"
    assert items[0].value == "/usr/bin:/bin"
    assert items[0].source_type == SourceType.PROC_ENVIRON

    assert items[2].key == "NODE_TLS_REJECT_UNAUTHORIZED"
    assert items[2].value == "0"

    assert items[3].key == "DB_PASSWORD"
    assert items[3].value == "SuperSecretPass123"


def test_read_mock_proc_file(tmp_path: Path) -> None:
    mock_file = tmp_path / "environ"
    raw = b"FLASK_ENV=development\x00PORT=5000\x00"
    mock_file.write_bytes(raw)

    parser = ProcParser()
    items = parser.read_file(mock_file, display_source="/proc/42/environ")

    assert len(items) == 2
    assert items[0].key == "FLASK_ENV"
    assert items[0].value == "development"
    assert items[0].source == "/proc/42/environ"


def test_missing_proc_file(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist"
    parser = ProcParser()
    with pytest.raises(ProcEnvironError, match="Process environ not found"):
        parser.read_file(missing)


def test_permission_denied_proc_file(tmp_path: Path) -> None:
    mock_file = tmp_path / "environ"
    mock_file.write_bytes(b"SECRET=val\x00")

    parser = ProcParser()
    with (
        patch("os.access", return_value=False),
        pytest.raises(ProcEnvironError, match="Permission denied"),
    ):
        parser.read_file(mock_file)


def test_empty_proc_environ() -> None:
    parser = ProcParser()
    items = parser.parse_bytes(b"", "/proc/1/environ")
    assert items == []
