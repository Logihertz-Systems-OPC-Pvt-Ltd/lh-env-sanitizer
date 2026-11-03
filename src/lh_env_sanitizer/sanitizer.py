# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.sanitizer
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Deterministic .env file sanitizer and template generator.

Transforms live .env files containing production secrets into safe,
documented .env.example templates with inferred type hints and placeholders.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse


class EnvSanitizer:
    """Sanitizes environment files into safe, deterministic .env.example files."""

    _LINE_RE = re.compile(r"^(\s*(?:export\s+)?)([A-Za-z0-9_.-]+)(\s*=\s*)(.*)$")

    _BOOL_PREFIXES = ("ENABLE_", "DISABLE_", "USE_", "IS_", "HAS_", "FEATURE_")
    _SECRET_KEYWORDS = ("PASSWORD", "PASSWD", "SECRET", "TOKEN", "KEY", "AUTH", "PRIVATE")

    def sanitize_file(self, input_path: Path, output_path: Path | None = None) -> str:
        """Sanitize a .env file and optionally save to an output file.

        Args:
            input_path: Path to the source .env file.
            output_path: Optional path to write the sanitized .env.example.

        Returns:
            The sanitized template string.
        """
        content = input_path.read_text(encoding="utf-8", errors="replace")
        sanitized = self.sanitize_string(content)

        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(sanitized, encoding="utf-8")

        return sanitized

    def sanitize_string(self, content: str) -> str:
        """Sanitize raw .env content string.

        Args:
            content: Raw .env file content.

        Returns:
            Sanitized .env.example content string.
        """
        output_lines: list[str] = []
        for line in content.splitlines():
            stripped = line.strip()

            # Preserve empty lines or pure comment lines
            if not stripped or stripped.startswith("#"):
                output_lines.append(line)
                continue

            match = self._LINE_RE.match(line)
            if not match:
                output_lines.append(line)
                continue

            prefix = match.group(1)
            key = match.group(2)
            equals = match.group(3)
            raw_val_part = match.group(4)

            placeholder, type_hint = self._infer_placeholder_and_type(key, raw_val_part)

            # Format sanitized line: KEY=placeholder # (type_hint)
            sanitized_line = f"{prefix}{key}{equals}{placeholder} # ({type_hint})"
            output_lines.append(sanitized_line)

        return "\n".join(output_lines) + ("\n" if content.endswith("\n") else "")

    def _infer_placeholder_and_type(self, key: str, raw_value: str) -> tuple[str, str]:
        """Infer safe placeholder value and descriptive type annotation."""
        key_upper = key.upper()
        clean_val = raw_value.strip().strip("'\"")

        # Strip existing inline comments if present in unquoted value
        if "#" in clean_val and not (raw_value.startswith(('"', "'"))):
            clean_val = clean_val.split("#", 1)[0].rstrip()

        # 1. Environment mode
        if key_upper in {"NODE_ENV", "APP_ENV", "ENVIRONMENT", "ENV", "FLASK_ENV"}:
            return "development", "string, enum: development|staging|production"

        # 2. Disabled TLS or Security flags
        if key_upper in {"NODE_TLS_REJECT_UNAUTHORIZED", "PYTHONHTTPSVERIFY"}:
            return "1", "boolean"

        # 3. Booleans and Debug
        if key_upper.startswith(self._BOOL_PREFIXES) or key_upper == "DEBUG":
            return "false", "boolean"
        if clean_val.lower() in {"true", "false"}:
            return "false", "boolean"

        # 4. Port numbers
        if key_upper.endswith("_PORT") or key_upper == "PORT":
            default_port = self._standard_port(key_upper, clean_val)
            return default_port, "integer, port"

        # 5. Connection URLs / Database URIs
        if "://" in clean_val or "DATABASE_URL" in key_upper or "DB_URI" in key_upper:
            url_placeholder = self._sanitize_url(clean_val, key_upper)
            return url_placeholder, "url"

        # 6. Hostnames / IPs
        if key_upper.endswith(("_HOST", "_HOSTNAME")) or key_upper in {"HOST", "HOSTNAME"}:
            return "localhost", "hostname/ip"

        # 7. Email addresses
        if "EMAIL" in key_upper or "MAIL" in key_upper or "@" in clean_val:
            return "admin@example.com", "email"

        # 8. Cryptographic secrets, API keys, and passwords
        if any(sec in key_upper for sec in self._SECRET_KEYWORDS):
            normalized_key = key.lower().replace("-", "_")
            return f"your_{normalized_key}_here", "string, secret"

        # 9. File paths
        if key_upper.endswith(("_PATH", "_DIR", "_FILE")) or clean_val.startswith(("/", "./")):
            return "/path/to/resource", "filepath"

        # 10. Numbers / Integers
        if clean_val.isdigit():
            return clean_val if int(clean_val) < 1000 else "10", "integer"

        # 11. Generic fallback string
        normalized_key = key.lower().replace("-", "_")
        return f"example_{normalized_key}", "string"

    @staticmethod
    def _standard_port(key_upper: str, current_val: str) -> str:
        """Provide appropriate standard default port."""
        if "REDIS" in key_upper:
            return "6379"
        if "MONGO" in key_upper:
            return "27017"
        if "POSTGRES" in key_upper or "PG" in key_upper:
            return "5432"
        if "MYSQL" in key_upper:
            return "3306"
        if current_val.isdigit() and 1 <= int(current_val) <= 65535:
            return current_val
        return "8080"

    @staticmethod
    def _sanitize_url(raw_url: str, key_upper: str) -> str:
        """Convert live connection URL to sanitized localhost template."""
        try:
            parsed = urlparse(raw_url)
            scheme = parsed.scheme.lower()
            if "postgres" in scheme or "pg" in key_upper:
                return "postgresql://user:password@localhost:5432/dbname"
            if "mysql" in scheme or "mysql" in key_upper:
                return "mysql://user:password@localhost:3306/dbname"
            if "mongo" in scheme or "mongo" in key_upper:
                return "mongodb://localhost:27017/dbname"
            if "redis" in scheme or "redis" in key_upper:
                return "redis://localhost:6379/0"
            if "amqp" in scheme or "rabbit" in key_upper:
                return "amqp://guest:guest@localhost:5672/"
            if scheme:
                return f"{scheme}://localhost:8080/resource"
        except (ValueError, AttributeError):
            return "https://api.example.com/v1"
        return "https://api.example.com/v1"
