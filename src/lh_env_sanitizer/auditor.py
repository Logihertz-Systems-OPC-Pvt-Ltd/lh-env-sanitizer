# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.auditor
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Core auditing engine coordinating parsers, security rules, and findings evaluation."""

from __future__ import annotations

from pathlib import Path

from lh_env_sanitizer.models import AuditResult, EnvItem, Finding
from lh_env_sanitizer.parsers.env_parser import DotenvParser
from lh_env_sanitizer.parsers.proc_parser import ProcParser
from lh_env_sanitizer.parsers.yaml_parser import YamlParser
from lh_env_sanitizer.rules import DEFAULT_RULES, Rule


class EnvironmentAuditor:
    """Audits environment and configuration files or process memory tables."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or DEFAULT_RULES
        self.dotenv_parser = DotenvParser()
        self.yaml_parser = YamlParser()
        self.proc_parser = ProcParser()

    def audit_path(self, target_path: Path) -> AuditResult:
        """Audit a file or recursively scan all environment/manifest files in a directory.

        Args:
            target_path: Path to a file or directory.

        Returns:
            Aggregated AuditResult with findings.
        """
        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        files_to_scan: list[Path] = []
        if target_path.is_file():
            files_to_scan.append(target_path)
        else:
            files_to_scan = self._discover_target_files(target_path)

        all_items: list[EnvItem] = []
        scanned_target_names: list[str] = []

        for f_path in files_to_scan:
            items = self._parse_file(f_path)
            all_items.extend(items)
            scanned_target_names.append(str(f_path))

        findings = self._evaluate_items(all_items)

        return AuditResult(
            target_path=str(target_path),
            scanned_targets=scanned_target_names,
            findings=findings,
            total_items_scanned=len(all_items),
        )

    def audit_proc(self, pid: int, environ_file: Path | None = None) -> AuditResult:
        """Audit process environment table from /proc/<pid>/environ or a mock file.

        Args:
            pid: Process ID.
            environ_file: Optional explicit path to /proc/<pid>/environ file.

        Returns:
            AuditResult containing detected issues.
        """
        if environ_file is not None:
            items = self.proc_parser.read_file(environ_file, display_source=f"/proc/{pid}/environ")
        else:
            items = self.proc_parser.read_pid_environ(pid)

        findings = self._evaluate_items(items)

        return AuditResult(
            target_path=f"/proc/{pid}/environ",
            scanned_targets=[f"/proc/{pid}/environ"],
            findings=findings,
            total_items_scanned=len(items),
        )

    def _discover_target_files(self, directory: Path) -> list[Path]:
        """Discover environment and manifest files recursively in directory."""
        candidates: list[Path] = []
        ignored_names = {
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.dist",
        }

        for path in directory.rglob("*"):
            if not path.is_file():
                continue

            # Ignore .git and .venv
            parts = path.parts
            if any(p in {".git", ".venv", "node_modules", "__pycache__"} for p in parts):
                continue

            name = path.name.lower()
            if name in ignored_names:
                continue

            # Match .env, .env.*
            if name == ".env" or name.startswith(".env."):
                candidates.append(path)
                continue

            # Match YAML files (compose, configmaps, manifests)
            if path.suffix in {".yaml", ".yml"}:
                candidates.append(path)
                continue

        return sorted(candidates)

    def _parse_file(self, file_path: Path) -> list[EnvItem]:
        """Select appropriate parser and extract EnvItems from file."""
        suffix = file_path.suffix.lower()
        name = file_path.name.lower()

        if suffix in {".yaml", ".yml"}:
            return self.yaml_parser.parse_file(file_path)

        # Dotenv files
        if name == ".env" or name.startswith(".env.") or suffix in {".env", ".local"}:
            return self.dotenv_parser.parse_file(file_path)

        # Default fallback: try dotenv first, if empty try yaml
        try:
            items = self.dotenv_parser.parse_file(file_path)
            if items:
                return items
        except (OSError, UnicodeDecodeError, ValueError):
            items = []

        try:
            return self.yaml_parser.parse_file(file_path)
        except (OSError, UnicodeDecodeError, ValueError):
            return []
        return []

    def _evaluate_items(self, items: list[EnvItem]) -> list[Finding]:
        """Run all configured security rules against parsed environment items."""
        findings: list[Finding] = []
        for item in items:
            for rule in self.rules:
                finding = rule.evaluate(item)
                if finding is not None:
                    findings.append(finding)
        return findings
