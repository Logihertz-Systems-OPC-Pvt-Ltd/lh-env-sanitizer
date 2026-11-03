# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        tests.test_sanitizer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the .env.example template sanitizer."""

from __future__ import annotations

from pathlib import Path

from lh_env_sanitizer.sanitizer import EnvSanitizer


def test_sanitize_env_string() -> None:
    live_env = """# Database Configuration
DATABASE_URL=postgres://prod_admin:UltraSecretPassword99@db.prod.internal:5432/main_db
DB_HOST=10.0.1.25
DB_PORT=5432
DB_PASSWORD=SuperP@ssw0rd

# Application Settings
NODE_ENV=production
DEBUG=true
PORT=3000
ADMIN_EMAIL=john.doe@company.corp
JWT_SECRET=super_secret_jwt_key_that_is_in_production
LOG_PATH=/var/log/application.log
MAX_WORKERS=16

# Security overrides (must fix!)
NODE_TLS_REJECT_UNAUTHORIZED=0
"""
    sanitizer = EnvSanitizer()
    sanitized = sanitizer.sanitize_string(live_env)

    # Comments and structure preserved
    assert "# Database Configuration" in sanitized
    assert "# Application Settings" in sanitized

    # Secrets replaced with placeholders
    assert "UltraSecretPassword99" not in sanitized
    assert "SuperP@ssw0rd" not in sanitized
    assert "super_secret_jwt_key_that_is_in_production" not in sanitized
    assert "john.doe@company.corp" not in sanitized

    # Type hints present
    assert "# (url)" in sanitized
    assert "# (hostname/ip)" in sanitized
    assert "# (integer, port)" in sanitized
    assert "# (string, secret)" in sanitized
    assert "# (boolean)" in sanitized
    assert "# (email)" in sanitized
    assert "# (filepath)" in sanitized
    assert "# (integer)" in sanitized
    assert "# (string, enum: development|staging|production)" in sanitized

    # Determinism: running again yields exact same string
    assert sanitizer.sanitize_string(live_env) == sanitized


def test_sanitize_various_urls_and_services() -> None:
    sanitizer = EnvSanitizer()

    content = (
        "MYSQL_URL=mysql://admin:pass123@sql.prod:3306/db\n"
        "MONGO_URI=mongodb://admin:secret@mongo.prod:27017/db\n"
        "REDIS_URL=redis://:auth123@cache.prod:6379/0\n"
        "RABBITMQ_URL=amqp://user:pass@mq.prod:5672/\n"
        "CUSTOM_URL=https://custom.api.internal:8443/endpoint\n"
        "REDIS_PORT=6379\n"
        "MONGO_PORT=27017\n"
        "PG_PORT=5432\n"
        "MYSQL_PORT=3306\n"
        "PYTHONHTTPSVERIFY=0\n"
        "EXPORTED_FLAG=export ENABLE_FEATURE=1\n"
        "export EXPORT_KEY=export_val\n"
        "LARGE_NUMBER=5000\n"
    )

    sanitized = sanitizer.sanitize_string(content)
    assert "postgresql://" not in sanitized or "mysql://" in sanitized
    assert "mysql://user:password@localhost:3306/dbname" in sanitized
    assert "mongodb://localhost:27017/dbname" in sanitized
    assert "redis://localhost:6379/0" in sanitized
    assert "amqp://guest:guest@localhost:5672/" in sanitized
    assert "6379" in sanitized
    assert "27017" in sanitized
    assert "5432" in sanitized
    assert "3306" in sanitized
    assert "export EXPORT_KEY" in sanitized


def test_sanitize_file(tmp_path: Path) -> None:
    in_file = tmp_path / ".env"
    in_file.write_text("API_KEY=ghp_secrettoken123\nPORT=8000\n", encoding="utf-8")

    out_file = tmp_path / ".env.example"

    sanitizer = EnvSanitizer()
    result = sanitizer.sanitize_file(in_file, output_path=out_file)

    assert out_file.exists()
    file_content = out_file.read_text(encoding="utf-8")
    assert file_content == result
    assert "ghp_secrettoken123" not in file_content
    assert "your_api_key_here" in file_content
