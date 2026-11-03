# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.parsers.env_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parser for .env and dotenv formatted configuration files."""

from __future__ import annotations

import re
from pathlib import Path

from lh_env_sanitizer.models import EnvItem, SourceType
from lh_env_sanitizer.parsers.base import BaseParser


class DotenvParser(BaseParser):
    """Parses .env configuration files, preserving line numbers and handling edge cases."""

    _LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z0-9_.-]+)\s*=\s*(.*)$")

    def parse_file(self, file_path: Path) -> list[EnvItem]:
        # --- Multi-Format Parsing & Normalization Engine ---
        # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
        # applies fallback decoders, recovers from malformed lines, and standardizes
        # raw configuration attributes into typed domain model instances.
        """Parse configuration items from a .env file.

        Args:
            file_path: Path to the .env file.

        Returns:
            List of parsed EnvItem instances.
        """
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return self.parse_string(content, source_name=str(file_path))

    def parse_string(self, content: str, source_name: str) -> list[EnvItem]:
        """Parse configuration items from a .env content string.

        Args:
            content: Raw .env file content.
            source_name: Name or path of the source file.

        Returns:
            List of parsed EnvItem instances.
        """
        items: list[EnvItem] = []
        lines = content.splitlines(keepends=True)
        idx = 0
        total_lines = len(lines)

        while idx < total_lines:
            raw_line = lines[idx]
            line_num = idx + 1
            stripped = raw_line.strip()

            # Skip empty lines or pure comment lines
            if not stripped or stripped.startswith("#"):
                idx += 1
                continue

            match = self._LINE_RE.match(stripped)
            if not match:
                idx += 1
                continue

            key = match.group(1)
            raw_val_part = match.group(2).strip()

            # Handle value parsing including multiline quotes
            value, consumed = self._extract_value(raw_val_part, lines, idx)
            idx += consumed

            items.append(
                EnvItem(
                    key=key,
                    value=value,
                    source=source_name,
                    source_type=SourceType.DOTENV,
                    line_number=line_num,
                )
            )

        return items

    def _extract_value(
        self, first_line_val: str, all_lines: list[str], start_idx: int
    ) -> tuple[str, int]:
        """Extract value taking into account single/double quotes and multiline blocks.

        Args:
            first_line_val: The value portion extracted from the initial line.
            all_lines: All lines in the document.
            start_idx: The current line index (0-based).

        Returns:
            Tuple of (parsed_value_string, lines_consumed_offset).
        """
        if not first_line_val:
            return "", 1

        first_char = first_line_val[0]

        # Quoted with double quote
        if first_char == '"':
            return self._parse_quoted(first_line_val, all_lines, start_idx, quote_char='"')

        # Quoted with single quote
        if first_char == "'":
            return self._parse_quoted(first_line_val, all_lines, start_idx, quote_char="'")

        # Unquoted value: inline comment starts at first '#'
        val = first_line_val
        if "#" in val:
            val = val.split("#", 1)[0].rstrip()

        return val, 1

    def _parse_quoted(
        self,
        first_line_val: str,
        all_lines: list[str],
        start_idx: int,
        quote_char: str,
    ) -> tuple[str, int]:
        """Parse single-line or multi-line quoted values."""
        # Check if closed on same line (ignoring escaped quotes)
        rest = first_line_val[1:]
        escaped = False
        close_pos = -1

        for i, ch in enumerate(rest):
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == quote_char:
                close_pos = i
                break

        if close_pos != -1:
            raw_inside = rest[:close_pos]
            val = self._unescape(raw_inside) if quote_char == '"' else raw_inside
            return val, 1

        # Multi-line quote
        accumulated = [rest]
        consumed = 1
        curr_idx = start_idx + 1
        total_lines = len(all_lines)

        while curr_idx < total_lines:
            line = all_lines[curr_idx]
            consumed += 1
            curr_idx += 1

            close_pos = -1
            escaped = False
            for i, ch in enumerate(line):
                if escaped:
                    escaped = False
                    continue
                if ch == "\\":
                    escaped = True
                    continue
                if ch == quote_char:
                    close_pos = i
                    break

            if close_pos != -1:
                accumulated.append(line[:close_pos])
                break
            accumulated.append(line)

        combined = "".join(accumulated)
        val = self._unescape(combined) if quote_char == '"' else combined
        return val, consumed

    @staticmethod
    def _unescape(text: str) -> str:
        """Decode common escape sequences in double-quoted strings."""
        return (
            text.replace(r"\n", "\n")
            .replace(r"\r", "\r")
            .replace(r"\t", "\t")
            .replace(r"\"", '"')
            .replace(r"\\", "\\")
        )
