# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.parsers.base
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Abstract base parser interface for environment configuration sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from lh_env_sanitizer.models import EnvItem


class BaseParser(ABC):
    """Abstract base class for all configuration source parsers."""

    @abstractmethod
    def parse_file(self, file_path: Path) -> list[EnvItem]:
        """Parse configuration items from a file on disk.

        Args:
            file_path: Path to the target file.

        Returns:
            List of parsed EnvItem instances.
        """

    @abstractmethod
    def parse_string(self, content: str, source_name: str) -> list[EnvItem]:
        """Parse configuration items from an in-memory string.

        Args:
            content: Raw file content to parse.
            source_name: Symbolic identifier or file name for reporting.

        Returns:
            List of parsed EnvItem instances.
        """
