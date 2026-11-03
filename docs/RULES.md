# Security Rules Reference: lh-env-sanitizer

An enterprise runtime environment & secret sanitizer developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-env-sanitizer`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-TLS-001` | `CRITICAL` | Transport Security | Disabled TLS Verification Flag in Environment |
| `LH-DBG-001` | `HIGH` | Configuration | Debug Mode Enabled in Production Environment |
| `LH-SEC-001` | `CRITICAL` | Secret Hygiene | Hardcoded Cloud Provider Access Keys and Private Tokens |
| `LH-SEC-002` | `HIGH` | Secret Hygiene | Hardcoded Generic Secrets or High-Entropy Passwords |
| `LH-SEC-003` | `HIGH` | Secret Hygiene | Plaintext Database Connection String Credentials |
| `LH-JWT-001` | `HIGH` | Cryptography | Weak or Dictionary-Based JWT Secret Key |
| `LH-K8S-001` | `HIGH` | Workload Security | Sensitive Credential Stored in Kubernetes ConfigMap |
| `LH-ENV-001` | `MEDIUM` | Configuration | Production Environment Schema Drift |
| `LH-PROC-001` | `CRITICAL` | Process Security | Cleartext Credential Exposed in Linux Process Environment |
| `LH-FILE-001` | `LOW` | Filesystem Security | Production .env File Missing Restricted Permissions |

---

## Granular Rule Specifications

### `LH-TLS-001`: Disabled TLS Verification Flag in Environment

- **Severity**: `CRITICAL`
- **Category**: `Transport Security`
- **Description**: Flags like NODE_TLS_REJECT_UNAUTHORIZED=0 or PYTHONHTTPSVERIFY=0 disable certificate validation.
- **Remediation**: Remove disabled TLS flags and install required internal CA certificates in trust store.

---

### `LH-DBG-001`: Debug Mode Enabled in Production Environment

- **Severity**: `HIGH`
- **Category**: `Configuration`
- **Description**: Variables like DEBUG=true or FLASK_ENV=development expose debug toolbars and stack traces.
- **Remediation**: Set DEBUG=false and configure production environment variables in deployment manifests.

---

### `LH-SEC-001`: Hardcoded Cloud Provider Access Keys and Private Tokens

- **Severity**: `CRITICAL`
- **Category**: `Secret Hygiene`
- **Description**: Live AWS, GCP, GitHub, or Stripe credentials embedded directly in environment files.
- **Remediation**: Purge credentials from repository files and inject via IAM roles or secret managers.

---

### `LH-SEC-002`: Hardcoded Generic Secrets or High-Entropy Passwords

- **Severity**: `HIGH`
- **Category**: `Secret Hygiene`
- **Description**: Plaintext passwords or high-entropy credentials declared in configuration file.
- **Remediation**: Replace plaintext passwords with environment variable references or vault injection.

---

### `LH-SEC-003`: Plaintext Database Connection String Credentials

- **Severity**: `HIGH`
- **Category**: `Secret Hygiene`
- **Description**: Embedded username and password credentials in database URIs (postgres://, mongodb://).
- **Remediation**: Externalize database credentials or use IAM database authentication.

---

### `LH-JWT-001`: Weak or Dictionary-Based JWT Secret Key

- **Severity**: `HIGH`
- **Category**: `Cryptography`
- **Description**: Short (< 32 chars) or common dictionary string used as JWT HMAC secret.
- **Remediation**: Generate cryptographically secure 256-bit+ random secret for JWT HMAC signing.

---

### `LH-K8S-001`: Sensitive Credential Stored in Kubernetes ConfigMap

- **Severity**: `HIGH`
- **Category**: `Workload Security`
- **Description**: Passwords or private tokens stored in unencrypted Kubernetes ConfigMap instead of Secret.
- **Remediation**: Migrate sensitive credentials to Kubernetes Secrets with encryption at rest or KMS provider.

---

### `LH-ENV-001`: Production Environment Schema Drift

- **Severity**: `MEDIUM`
- **Category**: `Configuration`
- **Description**: Production environment missing mandatory configuration keys declared in .env.example.
- **Remediation**: Synchronize production deployment variables with base template specifications.

---

### `LH-PROC-001`: Cleartext Credential Exposed in Linux Process Environment

- **Severity**: `CRITICAL`
- **Category**: `Process Security`
- **Description**: Sensitive credentials visible in /proc/<pid>/environ to unauthorized system users.
- **Remediation**: Pass credentials via secure in-memory files or IPC rather than process environment.

---

### `LH-FILE-001`: Production .env File Missing Restricted Permissions

- **Severity**: `LOW`
- **Category**: `Filesystem Security`
- **Description**: Production environment file has permissions looser than 0600.
- **Remediation**: Set restrictive filesystem permissions (chmod 600 .env) on all production configuration files.

---
