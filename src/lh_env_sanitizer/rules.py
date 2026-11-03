# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.rules
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Security and configuration audit rules for lh-env-sanitizer.

Evaluates parsed environment items against insecure flag, weak cryptographic,
and sensitive credential detection rules.
"""

from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from collections import Counter
from typing import ClassVar
from urllib.parse import urlparse

from lh_env_sanitizer.models import Confidence, EnvItem, Finding, Severity, SourceType


def calculate_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def is_placeholder(value: str) -> bool:
    """Check if a string represents an obvious placeholder or documentation stub."""
    val_lower = value.strip().lower()
    placeholders = {
        "changeme",
        "placeholder",
        "example",
        "sample",
        "dummy",
        "todo",
        "replace_me",
        "your_secret_here",
        "your_api_key_here",
        "your_password_here",
        "none",
        "null",
        "undefined",
        "xxx",
        "xxxx",
        "test",
        "demo",
        "password",
        "pass",
        "secret",
    }
    if val_lower in placeholders:
        return True
    if any(p in val_lower for p in ("your_", "replace_me", "example.com", "changeme")):
        return True
    return bool(val_lower.startswith("<") and val_lower.endswith(">"))


def mask_secret(value: str) -> str:
    """Safely mask secret strings to prevent accidental credential leakage in logs."""
    if not value:
        return ""
    length = len(value)
    if length <= 6:
        return "***"
    if length <= 12:
        return f"{value[:2]}****{value[-2:]}"
    return f"{value[:4]}****{value[-4:]}"


class Rule(ABC):
    """Abstract base class for environment security audit rules."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    cwe_id: str
    recommendation: str

    @abstractmethod
    def evaluate(self, item: EnvItem) -> Finding | None:
        """Evaluate an EnvItem against this rule.

        Args:
            item: The parsed environment item to check.

        Returns:
            A Finding if an issue is detected, or None if clean.
        """

    def create_finding(
        self,
        item: EnvItem,
        description: str | None = None,
        severity: Severity | None = None,
        recommendation: str | None = None,
        confidence: Confidence | None = None,
    ) -> Finding:
        """Helper to instantiate a standardized Finding from this rule."""
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            description=description or self.description,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
            key=item.key,
            value_masked=mask_secret(item.value),
            source=item.source,
            line_number=item.line_number,
            recommendation=recommendation or self.recommendation,
            cwe_id=self.cwe_id,
        )


class TlsVerificationDisabledRule(Rule):
    """Detects flags that disable TLS/SSL certificate validation."""

    rule_id = "LH-TLS-001"
    title = "Disabled TLS Verification Flag"
    description = (
        "TLS certificate verification has been explicitly disabled. "
        "This exposes network communications to Man-in-the-Middle (MitM) attacks."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe_id = "CWE-295"
    recommendation = (
        "Re-enable TLS certificate validation immediately. "
        "Do not disable verification in production or pre-deployment environments."
    )

    _DISABLED_VALUES = {"0", "false", "no", "off", "disable", "disabled"}
    _EMPTY_OR_NULL = {"", "/dev/null", "none", "false"}

    def evaluate(self, item: EnvItem) -> Finding | None:
        key_upper = item.key.strip().upper()
        val_clean = item.value.strip().strip("'\"").lower()

        # Node.js
        if key_upper == "NODE_TLS_REJECT_UNAUTHORIZED" and val_clean in self._DISABLED_VALUES:
            return self.create_finding(
                item,
                description=(
                    "NODE_TLS_REJECT_UNAUTHORIZED is set to disable certificate validation."
                ),
            )

        # Python
        if key_upper == "PYTHONHTTPSVERIFY" and val_clean in self._DISABLED_VALUES:
            return self.create_finding(
                item,
                description="PYTHONHTTPSVERIFY is set to disable HTTPS certificate verification.",
            )

        # Git
        if key_upper == "GIT_SSL_NO_VERIFY" and val_clean in {"1", "true", "yes", "on"}:
            return self.create_finding(
                item,
                description=(
                    "GIT_SSL_NO_VERIFY is enabled, disabling TLS validation for Git operations."
                ),
            )

        # Curl / Requests CA Bundles pointing to /dev/null or empty
        if key_upper in {"CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE"} and (
            val_clean in self._EMPTY_OR_NULL
        ):
            return self.create_finding(
                item,
                description=f"{key_upper} is empty or disabled, bypassing certificate validation.",
            )

        if key_upper == "SSL_CERT_FILE" and val_clean == "/dev/null":
            return self.create_finding(
                item,
                description="SSL_CERT_FILE points to /dev/null, disabling root CA verification.",
            )

        if key_upper == "PERL_LWP_SSL_VERIFY_HOSTNAME" and val_clean in self._DISABLED_VALUES:
            return self.create_finding(
                item,
                description="PERL_LWP_SSL_VERIFY_HOSTNAME is set to disable hostname validation.",
            )

        return None


class DebugModeEnabledRule(Rule):
    """Detects active debug flags and development environments."""

    rule_id = "LH-DBG-001"
    title = "Debug Mode Enabled in Runtime Configuration"
    description = (
        "Debug mode or development environment is activated. "
        "This may expose detailed stack traces, sensitive configurations, or interactive debuggers."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe_id = "CWE-489"
    recommendation = (
        "Set debug flags to false (e.g. DEBUG=false) and set environment variables "
        "to production (e.g. NODE_ENV=production, FLASK_ENV=production)."
    )

    _TRUTHY_VALUES = {"1", "true", "yes", "on", "enable", "enabled"}
    _DEV_VALUES = {"development", "dev", "local", "debug"}

    def evaluate(self, item: EnvItem) -> Finding | None:
        key_upper = item.key.strip().upper()
        val_clean = item.value.strip().strip("'\"").lower()

        # Generic DEBUG / APP_DEBUG
        is_debug_key = key_upper in {"DEBUG", "APP_DEBUG", "DJANGO_DEBUG", "FASTAPI_DEBUG"}
        if is_debug_key and val_clean in self._TRUTHY_VALUES:
            return self.create_finding(
                item,
                description=f"{item.key} is enabled ({item.value}), activating debug handlers.",
            )

        # Flask
        if key_upper == "FLASK_ENV" and val_clean in self._DEV_VALUES:
            return self.create_finding(
                item,
                description="FLASK_ENV is set to development mode.",
            )
        if key_upper == "FLASK_DEBUG" and val_clean in self._TRUTHY_VALUES:
            return self.create_finding(
                item,
                description="FLASK_DEBUG is enabled, exposing the interactive Werkzeug debugger.",
            )

        # Node / Rails
        if key_upper in {"NODE_ENV", "RAILS_ENV"} and val_clean in self._DEV_VALUES:
            return self.create_finding(
                item,
                description=f"{key_upper} is configured for development mode.",
                severity=Severity.MEDIUM,
            )

        return None


class HardcodedCloudSecretsRule(Rule):
    """Detects hardcoded cloud credentials, tokens, and private keys."""

    rule_id = "LH-SEC-001"
    title = "Hardcoded Production Secret or API Key"
    description = (
        "Detected a hardcoded API token, cloud provider access key, or private cryptographic key."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe_id = "CWE-798"
    recommendation = (
        "Remove hardcoded credentials. Store secrets in a secure secret manager "
        "(e.g. AWS Secrets Manager, HashiCorp Vault, Kubernetes Secret) and inject at runtime."
    )

    _PATTERNS: ClassVar[list[tuple[str, re.Pattern[str]]]] = [
        ("AWS Access Key ID", re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b")),
        ("GitHub PAT", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[0-9a-zA-Z]{36}\b")),
        ("GitHub Fine-Grained Token", re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b")),
        (
            "Slack Token",
            re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9]*-?[a-zA-Z0-9]{24,32}\b"),
        ),
        ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
        ("Private Key Block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
        ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
        ("SendGrid API Key", re.compile(r"\bSG\.[0-9a-zA-Z_\-]{22}\.[0-9a-zA-Z_\-]{43}\b")),
        ("OpenAI API Key", re.compile(r"\bsk-(?:proj-)?[0-9a-zA-Z\-_]{32,}\b")),
    ]

    _AWS_SECRET_RE = re.compile(r"^[0-9a-zA-Z/+]{40}$")

    def evaluate(self, item: EnvItem) -> Finding | None:
        val = item.value.strip().strip("'\"")
        if not val or is_placeholder(val):
            return None

        # Check explicit patterns
        for label, pattern in self._PATTERNS:
            if pattern.search(val):
                return self.create_finding(
                    item,
                    description=f"Detected hardcoded {label}.",
                )

        # Check AWS Secret Key when paired with relevant key name
        key_upper = item.key.strip().upper()
        if "AWS_SECRET" in key_upper and self._AWS_SECRET_RE.match(val):
            return self.create_finding(
                item,
                description="Detected AWS Secret Access Key in configuration.",
            )

        return None


class WeakJwtSecretRule(Rule):
    """Detects weak, short, or default JSON Web Token (JWT) secret keys."""

    rule_id = "LH-JWT-001"
    title = "Weak or Insecure JWT Secret"
    description = (
        "The JWT signing secret is either using a common default password, is too short, "
        "or exhibits low entropy, making it vulnerable to offline dictionary/brute-force attacks."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe_id = "CWE-326"
    recommendation = (
        "Generate a cryptographically secure random key of at least 32 bytes (256 bits) "
        "using a CSPRNG (e.g. `openssl rand -hex 32`)."
    )

    _JWT_KEYS = {
        "JWT_SECRET",
        "JWT_KEY",
        "JWT_SECRET_KEY",
        "TOKEN_SECRET",
        "APP_KEY",
        "SECRET_KEY_BASE",
    }

    _COMMON_SECRETS = {
        "secret",
        "secret123",
        "jwtsecret",
        "test",
        "password",
        "123456",
        "admin",
        "key",
        "mysecret",
        "changeme",
        "jwt_secret",
        "supersecret",
        "default",
        "secretkey",
    }

    def evaluate(self, item: EnvItem) -> Finding | None:
        key_upper = item.key.strip().upper()
        if not any(k in key_upper for k in self._JWT_KEYS):
            return None

        val = item.value.strip().strip("'\"")
        if not val or is_placeholder(val):
            return None

        val_lower = val.lower()

        # 1. Common dictionary value
        if val_lower in self._COMMON_SECRETS:
            masked = mask_secret(val)
            return self.create_finding(
                item,
                description=f"JWT secret is set to a well-known weak passphrase: '{masked}'.",
            )

        # 2. Key length < 32 characters (less than 256 bits)
        if len(val) < 32:
            return self.create_finding(
                item,
                description=(
                    f"JWT secret length ({len(val)} characters) is below the recommended "
                    f"minimum of 32 characters (256 bits) for HMAC-SHA256."
                ),
            )

        # 3. Low Shannon entropy (< 3.0 bits/char)
        entropy = calculate_entropy(val)
        if entropy < 3.0:
            return self.create_finding(
                item,
                description=(
                    f"JWT secret exhibits low entropy ({entropy:.2f} bits/char). "
                    "Cryptographic signing keys require high randomness."
                ),
                confidence=Confidence.MEDIUM,
            )

        return None


class ConnectionUriCredentialsRule(Rule):
    """Detects plaintext credentials embedded in database or service connection URIs."""

    rule_id = "LH-SEC-003"
    title = "Plaintext Credentials in Connection URI"
    description = (
        "A connection string or database URI contains hardcoded username and password credentials."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe_id = "CWE-798"
    recommendation = (
        "Remove hardcoded credentials from connection strings. "
        "Use cloud IAM authentication or reference runtime secrets."
    )

    _SCHEMES = {
        "postgres",
        "postgresql",
        "mysql",
        "mongodb",
        "redis",
        "rediss",
        "amqp",
        "amqps",
        "mssql",
        "oracle",
    }

    def evaluate(self, item: EnvItem) -> Finding | None:
        val = item.value.strip().strip("'\"")
        if not val or is_placeholder(val):
            return None

        # Check for scheme://...
        if "://" not in val:
            return None

        try:
            parsed = urlparse(val)
        except Exception:
            return None

        if parsed.scheme.lower() not in self._SCHEMES:
            return None

        if parsed.password:
            # Check if password is just an obvious placeholder
            if is_placeholder(parsed.password):
                return None
            return self.create_finding(
                item,
                description=(
                    f"Connection URI for '{parsed.scheme}' contains plaintext password credentials."
                ),
            )

        return None


class KubernetesConfigMapSecretRule(Rule):
    """Detects sensitive credentials stored directly in a Kubernetes ConfigMap."""

    rule_id = "LH-K8S-001"
    title = "Sensitive Secret Stored in Kubernetes ConfigMap"
    description = (
        "A Kubernetes ConfigMap contains sensitive credentials. "
        "ConfigMaps are unencrypted and visible to any workload or user with ConfigMap permissions."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe_id = "CWE-312"
    recommendation = (
        "Migrate sensitive credentials from ConfigMap to a Kubernetes Secret "
        "or an external secrets store (e.g. HashiCorp Vault, AWS Secrets Manager)."
    )

    _SENSITIVE_KEY_RE = re.compile(
        r"(?:password|passwd|secret|api_key|apikey|token|private_key|auth_token|credentials)",
        re.IGNORECASE,
    )

    def evaluate(self, item: EnvItem) -> Finding | None:
        if item.source_type != SourceType.K8S_CONFIGMAP:
            return None

        val = item.value.strip().strip("'\"")
        if not val or is_placeholder(val):
            return None

        if self._SENSITIVE_KEY_RE.search(item.key):
            cm_name = item.context.get("name", "unknown")
            return self.create_finding(
                item,
                description=(
                    f"Sensitive key '{item.key}' defined directly in ConfigMap '{cm_name}'. "
                    "Credentials should be stored in Kubernetes Secrets."
                ),
            )

        return None


class HardcodedGenericSecretRule(Rule):
    """Detects generic passwords, secret keys, and high-entropy authentication tokens."""

    rule_id = "LH-SEC-002"
    title = "Hardcoded Password or Generic Secret Key"
    description = "Detected a hardcoded password, API key, or authentication secret."
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    cwe_id = "CWE-798"
    recommendation = (
        "Never commit plaintext passwords or secrets to configuration files. "
        "Inject credentials via environment variables from a secure secrets provider."
    )

    _SECRET_KEY_RE = re.compile(
        r"^(?:DB_PASSWORD|DATABASE_PASSWORD|REDIS_PASSWORD|POSTGRES_PASSWORD|"
        r"MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|ADMIN_PASSWORD|APP_SECRET|"
        r"SECRET_KEY|API_KEY|AUTH_TOKEN|ACCESS_TOKEN)$",
        re.IGNORECASE,
    )

    def evaluate(self, item: EnvItem) -> Finding | None:
        val = item.value.strip().strip("'\"")
        if not val or is_placeholder(val):
            return None

        # Check if key matches password/secret naming patterns
        if self._SECRET_KEY_RE.match(item.key) and len(val) >= 4:
            return self.create_finding(
                item,
                description=f"Hardcoded sensitive value for '{item.key}'.",
            )

        return None


DEFAULT_RULES: list[Rule] = [
    TlsVerificationDisabledRule(),
    DebugModeEnabledRule(),
    HardcodedCloudSecretsRule(),
    WeakJwtSecretRule(),
    ConnectionUriCredentialsRule(),
    KubernetesConfigMapSecretRule(),
    HardcodedGenericSecretRule(),
]
