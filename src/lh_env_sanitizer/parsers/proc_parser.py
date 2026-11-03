# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.parsers.proc_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parser and reader for Linux /proc/<pid>/environ process memory blocks."""

from __future__ import annotations

import os
from pathlib import Path

from lh_env_sanitizer.models import EnvItem, SourceType


class ProcEnvironError(Exception):
    """Exception raised when accessing or parsing /proc/<pid>/environ fails."""


class ProcParser:
    """Inspects Linux /proc/<pid>/environ to extract process runtime environment tables."""

    def read_pid_environ(self, pid: int) -> list[EnvItem]:
        """Read and parse environment variables for a running process by PID.

        Args:
            pid: Process ID to inspect.

        Returns:
            List of parsed EnvItem instances.

        Raises:
            ProcEnvironError: If process does not exist, permission is denied, or read fails.
        """
        proc_path = Path(f"/proc/{pid}/environ")
        return self.read_file(proc_path, display_source=f"/proc/{pid}/environ")

    def read_file(self, file_path: Path, display_source: str | None = None) -> list[EnvItem]:
        """Read and parse environment variables from a /proc environ file path.

        Args:
            file_path: Path to the environ file (e.g. /proc/<pid>/environ or mock path).
            display_source: Friendly label for reporting. Defaults to file_path string.

        Returns:
            List of parsed EnvItem instances.

        Raises:
            ProcEnvironError: On filesystem or access errors.
        """
        source_label = display_source or str(file_path)

        if not file_path.exists():
            raise ProcEnvironError(
                f"Process environ not found: '{source_label}'. "
                f"Process might not exist or has already terminated."
            )

        if not os.access(file_path, os.R_OK):
            raise ProcEnvironError(
                f"Permission denied reading '{source_label}'. "
                f"Root privileges (sudo) or CAP_SYS_PTRACE may be required."
            )

        try:
            raw_bytes = file_path.read_bytes()
        except PermissionError as err:
            raise ProcEnvironError(f"Permission denied reading '{source_label}': {err}") from err
        except OSError as err:
            raise ProcEnvironError(
                f"Error reading process environment from '{source_label}': {err}"
            ) from err

        return self.parse_bytes(raw_bytes, source_label)

    def parse_bytes(self, raw_bytes: bytes, source_name: str) -> list[EnvItem]:
        # --- Multi-Format Parsing & Normalization Engine ---
        # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
        # applies fallback decoders, recovers from malformed lines, and standardizes
        # raw configuration attributes into typed domain model instances.
        """Parse null-byte separated environ bytes.

        Args:
            raw_bytes: Binary buffer separated by b'\\x00'.
            source_name: Source identifier for findings.

        Returns:
            List of parsed EnvItem instances.
        """
        items: list[EnvItem] = []
        entries = raw_bytes.split(b"\x00")

        line_index = 1
        for entry in entries:
            if not entry:
                continue

            # Decode safely
            decoded = entry.decode("utf-8", errors="replace")
            if "=" in decoded:
                key, val = decoded.split("=", 1)
            else:
                key = decoded
                val = ""

            items.append(
                EnvItem(
                    key=key,
                    value=val,
                    source=source_name,
                    source_type=SourceType.PROC_ENVIRON,
                    line_number=line_index,
                )
            )
            line_index += 1

        return items
