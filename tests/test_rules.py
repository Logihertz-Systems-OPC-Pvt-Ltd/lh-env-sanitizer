# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        tests.test_rules
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for security rules, secret detection, and TLS/debug flags."""

from __future__ import annotations

from lh_env_sanitizer.models import EnvItem, Severity, SourceType
from lh_env_sanitizer.rules import (
    ConnectionUriCredentialsRule,
    DebugModeEnabledRule,
    HardcodedCloudSecretsRule,
    HardcodedGenericSecretRule,
    KubernetesConfigMapSecretRule,
    TlsVerificationDisabledRule,
    WeakJwtSecretRule,
    calculate_entropy,
    is_placeholder,
    mask_secret,
)


def _make_item(key: str, value: str, source_type: SourceType = SourceType.DOTENV) -> EnvItem:
    return EnvItem(
        key=key,
        value=value,
        source=".env",
        source_type=source_type,
        line_number=1,
    )


def test_tls_verification_disabled_rule() -> None:
    rule = TlsVerificationDisabledRule()

    # Node.js
    f1 = rule.evaluate(_make_item("NODE_TLS_REJECT_UNAUTHORIZED", "0"))
    assert f1 is not None
    assert f1.severity == Severity.CRITICAL
    assert f1.rule_id == "LH-TLS-001"

    # Python
    f2 = rule.evaluate(_make_item("PYTHONHTTPSVERIFY", "0"))
    assert f2 is not None

    # Git
    f3 = rule.evaluate(_make_item("GIT_SSL_NO_VERIFY", "true"))
    assert f3 is not None

    # Empty CA Bundle
    f4 = rule.evaluate(_make_item("CURL_CA_BUNDLE", ""))
    assert f4 is not None

    # Clean values
    assert rule.evaluate(_make_item("NODE_TLS_REJECT_UNAUTHORIZED", "1")) is None
    assert rule.evaluate(_make_item("PYTHONHTTPSVERIFY", "1")) is None


def test_debug_mode_enabled_rule() -> None:
    rule = DebugModeEnabledRule()

    f1 = rule.evaluate(_make_item("DEBUG", "true"))
    assert f1 is not None
    assert f1.severity == Severity.HIGH
    assert f1.rule_id == "LH-DBG-001"

    f2 = rule.evaluate(_make_item("FLASK_ENV", "development"))
    assert f2 is not None

    f3 = rule.evaluate(_make_item("FLASK_DEBUG", "1"))
    assert f3 is not None

    f4 = rule.evaluate(_make_item("NODE_ENV", "dev"))
    assert f4 is not None

    # Clean
    assert rule.evaluate(_make_item("DEBUG", "false")) is None
    assert rule.evaluate(_make_item("FLASK_ENV", "production")) is None
    assert rule.evaluate(_make_item("NODE_ENV", "production")) is None


def test_hardcoded_cloud_secrets_rule() -> None:
    rule = HardcodedCloudSecretsRule()

    # AWS Access Key ID
    f_aws = rule.evaluate(_make_item("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"))
    assert f_aws is not None
    assert f_aws.severity == Severity.CRITICAL

    # GitHub PAT
    f_gh = rule.evaluate(_make_item("GITHUB_TOKEN", "ghp_123456789012345678901234567890123456"))
    assert f_gh is not None

    # Google API Key
    f_gcp = rule.evaluate(_make_item("GCP_KEY", "AIzaSyD-1234567890123456789012345678901"))
    assert f_gcp is not None

    # Stripe Secret Key
    f_stripe = rule.evaluate(_make_item("STRIPE_KEY", "sk_" + "live_123456789012345678901234"))
    assert f_stripe is not None

    # Private Key
    f_pk = rule.evaluate(_make_item("SSL_KEY", "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."))
    assert f_pk is not None

    # Placeholders ignored
    assert rule.evaluate(_make_item("API_KEY", "your_api_key_here")) is None
    assert rule.evaluate(_make_item("GITHUB_TOKEN", "changeme")) is None


def test_weak_jwt_secret_rule() -> None:
    rule = WeakJwtSecretRule()

    # Dictionary secret
    f_dict = rule.evaluate(_make_item("JWT_SECRET", "secret123"))
    assert f_dict is not None
    assert "well-known weak passphrase" in f_dict.description

    # Short secret
    f_short = rule.evaluate(_make_item("JWT_SECRET", "short_secret_key_123"))
    assert f_short is not None
    assert "below the recommended minimum" in f_short.description

    # Low entropy repeated secret
    f_entropy = rule.evaluate(_make_item("JWT_SECRET", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    assert f_entropy is not None
    assert "low entropy" in f_entropy.description

    # Strong 256-bit secret
    strong = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert rule.evaluate(_make_item("JWT_SECRET", strong)) is None


def test_connection_uri_credentials_rule() -> None:
    rule = ConnectionUriCredentialsRule()

    # Plaintext credentials
    uri = "postgres://appuser:SuperSecretPass123@db.prod.internal:5432/main_db"
    f1 = rule.evaluate(_make_item("DATABASE_URL", uri))
    assert f1 is not None
    assert "postgres" in f1.description

    # Placeholder password ignored
    placeholder_uri = "postgres://user:password@localhost:5432/mydb"
    assert rule.evaluate(_make_item("DATABASE_URL", placeholder_uri)) is None

    # Non-database URI
    assert rule.evaluate(_make_item("WEB_URL", "https://example.com/api")) is None


def test_k8s_configmap_secret_rule() -> None:
    rule = KubernetesConfigMapSecretRule()

    cm_item = EnvItem(
        key="DB_PASSWORD",
        value="MySecretPassword",
        source="k8s.yaml",
        source_type=SourceType.K8S_CONFIGMAP,
        line_number=10,
        context={"name": "my-configmap"},
    )
    f = rule.evaluate(cm_item)
    assert f is not None
    assert "my-configmap" in f.description

    # Safe ConfigMap item
    safe_item = EnvItem(
        key="LOG_LEVEL",
        value="INFO",
        source="k8s.yaml",
        source_type=SourceType.K8S_CONFIGMAP,
    )
    assert rule.evaluate(safe_item) is None

    # Non-ConfigMap item ignored by this rule
    non_cm = _make_item("DB_PASSWORD", "MySecretPassword")
    assert rule.evaluate(non_cm) is None


def test_generic_secret_rule() -> None:
    rule = HardcodedGenericSecretRule()

    f = rule.evaluate(_make_item("DB_PASSWORD", "RealProdSecret99!"))
    assert f is not None

    # Placeholder
    assert rule.evaluate(_make_item("DB_PASSWORD", "changeme")) is None


def test_helpers() -> None:
    assert is_placeholder("changeme")
    assert is_placeholder("<YOUR_KEY>")
    assert not is_placeholder("aB3$9xL!z82qW")

    assert mask_secret("") == ""
    assert mask_secret("short") == "***"
    assert "secret" not in mask_secret("supersecretvalue123456")

    ent = calculate_entropy("aaaa")
    assert ent == 0.0
    assert calculate_entropy("abcdefghijklmnop") > 3.5
