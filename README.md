# lh-env-sanitizer

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-env-sanitizer/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-env-sanitizer/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise environment & configuration secret hygiene developed by **Logihertz Systems (OPC) Private Limited**.

Scans .env files, Kubernetes ConfigMaps, Docker environment blocks, and CI variable dumps using Shannon entropy and pattern matching to detect cleartext API keys, debug flags in production, and weak secrets; outputs redacted templates.

---

## Key Features

- **Multi-Source Environment Auditing**: Parses local `.env` files, Docker Compose, Kubernetes ConfigMaps, and live Linux process tables.
- **Secret Exposure Scanning**: Detects AWS/GCP keys, GitHub tokens, Slack webhooks, and private RSA/EC keys via Shannon entropy and regex.
- **Debug Flag & Insecure Transport Detection**: Flags `DEBUG=true`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, and `PYTHONHTTPSVERIFY=0`.
- **Automated Safe Template Generation**: Generates deterministic `.env.example` templates with sanitized placeholder values and type hints.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-TLS-001` | `CRITICAL` | Disabled TLS verification flag (NODE_TLS_REJECT_UNAUTHORIZED=0, PYTHONHTTPSVERIFY=0) |
| `LH-DBG-001` | `HIGH` | Debug mode enabled in production (DEBUG=true, FLASK_ENV=development) |
| `LH-SEC-001` | `CRITICAL` | Hardcoded cloud provider access keys and private tokens (AWS, GCP, GitHub) |
| `LH-SEC-002` | `HIGH` | Hardcoded generic secrets, API keys, or high-entropy credentials in environment |
| `LH-SEC-003` | `HIGH` | Plaintext database connection string credentials (postgres://, mongodb://) |
| `LH-JWT-001` | `HIGH` | Weak, short, or dictionary-based JWT secret key (< 32 characters) |
| `LH-K8S-001` | `HIGH` | Sensitive credential or private token stored unencrypted in Kubernetes ConfigMap |
| `LH-ENV-001` | `MEDIUM` | Production environment schema drift or missing mandatory variable |
| `LH-PROC-001` | `CRITICAL` | Cleartext credential exposed in Linux process environment (/proc/<pid>/environ) |
| `LH-FILE-001` | `LOW` | Production .env file lacking restricted filesystem permissions (mode > 0600) |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-env-sanitizer.git
cd lh-env-sanitizer

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-env` (also accessible via `lh-env`).

```bash
# Audit a single .env file for secrets and debug flags
lh-env audit .env

# Generate safe .env.example template from existing .env
lh-env sanitize .env --output .env.example

# Audit a running Linux process environment
lh-env scan-proc --pid 1234 --format json

# Export findings to OASIS SARIF v2.1.0
lh-env audit ./configs/ --format sarif --output env-results.sarif
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
