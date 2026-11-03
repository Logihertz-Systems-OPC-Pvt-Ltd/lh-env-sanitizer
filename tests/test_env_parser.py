# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        tests.test_env_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the .env parser."""

from __future__ import annotations

from pathlib import Path

from lh_env_sanitizer.models import SourceType
from lh_env_sanitizer.parsers.env_parser import DotenvParser


def test_parse_simple_env() -> None:
    content = "KEY1=value1\nKEY2=value2\n"
    parser = DotenvParser()
    items = parser.parse_string(content, "test.env")

    assert len(items) == 2
    assert items[0].key == "KEY1"
    assert items[0].value == "value1"
    assert items[0].line_number == 1
    assert items[0].source_type == SourceType.DOTENV

    assert items[1].key == "KEY2"
    assert items[1].value == "value2"
    assert items[1].line_number == 2


def test_parse_with_export_and_comments() -> None:
    content = (
        "# Configuration section\n"
        "\n"
        "export APP_NAME=demo-app # Application title\n"
        "export PORT=8080\n"
    )
    parser = DotenvParser()
    items = parser.parse_string(content, "test.env")

    assert len(items) == 2
    assert items[0].key == "APP_NAME"
    assert items[0].value == "demo-app"
    assert items[0].line_number == 3

    assert items[1].key == "PORT"
    assert items[1].value == "8080"
    assert items[1].line_number == 4


def test_parse_quotes_and_escapes() -> None:
    content = (
        'DOUBLE_QUOTED="hello\\nworld"\n'
        "SINGLE_QUOTED='literal # with comment'\n"
        'ESCAPED_QUOTE="quote \\"inside\\""\n'
    )
    parser = DotenvParser()
    items = parser.parse_string(content, "test.env")

    assert len(items) == 3
    assert items[0].key == "DOUBLE_QUOTED"
    assert items[0].value == "hello\nworld"

    assert items[1].key == "SINGLE_QUOTED"
    assert items[1].value == "literal # with comment"

    assert items[2].key == "ESCAPED_QUOTE"
    assert items[2].value == 'quote "inside"'


def test_parse_multiline_double_quote() -> None:
    content = (
        'CERTIFICATE="-----BEGIN CERT-----\n'
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"
        '-----END CERT-----"\n'
        "NEXT_KEY=123\n"
    )
    parser = DotenvParser()
    items = parser.parse_string(content, "test.env")

    assert len(items) == 2
    assert items[0].key == "CERTIFICATE"
    assert "-----BEGIN CERT-----" in items[0].value
    assert items[0].line_number == 1

    assert items[1].key == "NEXT_KEY"
    assert items[1].value == "123"
    assert items[1].line_number == 4


def test_parse_file_on_disk(tmp_path: Path) -> None:
    env_file = tmp_path / ".env.test"
    env_file.write_text("DATABASE_URL=postgres://localhost/db\n", encoding="utf-8")

    parser = DotenvParser()
    items = parser.parse_file(env_file)

    assert len(items) == 1
    assert items[0].key == "DATABASE_URL"
    assert items[0].source == str(env_file)
