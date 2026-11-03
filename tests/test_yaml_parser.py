# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        tests.test_yaml_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the YAML parser (Docker Compose, Kubernetes ConfigMaps)."""

from __future__ import annotations

from pathlib import Path

from lh_env_sanitizer.models import SourceType
from lh_env_sanitizer.parsers.yaml_parser import YamlParser


def test_parse_docker_compose_dict() -> None:
    yaml_content = """
version: '3.8'
services:
  web:
    image: nginx
    environment:
      NODE_ENV: production
      PORT: 8080
      DEBUG: "true"
"""
    parser = YamlParser()
    items = parser.parse_string(yaml_content, "docker-compose.yml")

    assert len(items) == 3
    keys = {item.key: item.value for item in items}
    assert keys["NODE_ENV"] == "production"
    assert keys["PORT"] == "8080"
    assert keys["DEBUG"] == "true"

    for item in items:
        assert item.source_type == SourceType.DOCKER_COMPOSE
        assert item.context.get("service") == "web"
        assert item.line_number is not None


def test_parse_docker_compose_list() -> None:
    yaml_content = """
services:
  api:
    image: backend:latest
    environment:
      - DATABASE_URL=postgres://user:pass@localhost:5432/db
      - REDIS_HOST=cache
      - FLASK_ENV=development
"""
    parser = YamlParser()
    items = parser.parse_string(yaml_content, "docker-compose.yml")

    assert len(items) == 3
    keys = {item.key: item.value for item in items}
    assert "DATABASE_URL" in keys
    assert keys["REDIS_HOST"] == "cache"
    assert keys["FLASK_ENV"] == "development"


def test_parse_kubernetes_configmap() -> None:
    yaml_content = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: production
data:
  APP_ENV: production
  MAX_CLIENTS: "100"
  LOG_LEVEL: info
binaryData:
  ENCODED_FLAG: "dHJ1ZQ=="
"""
    parser = YamlParser()
    items = parser.parse_string(yaml_content, "configmap.yaml")

    assert len(items) == 4
    keys = {item.key: item.value for item in items}
    assert keys["APP_ENV"] == "production"
    assert keys["MAX_CLIENTS"] == "100"
    assert keys["ENCODED_FLAG"] == "dHJ1ZQ=="

    for item in items:
        assert item.source_type == SourceType.K8S_CONFIGMAP
        assert item.context.get("kind") == "ConfigMap"
        assert item.context.get("name") == "app-config"
        assert item.context.get("namespace") == "production"


def test_parse_kubernetes_deployment() -> None:
    yaml_content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-deployment
spec:
  template:
    spec:
      containers:
        - name: web-app
          image: app:v1
          env:
            - name: NODE_TLS_REJECT_UNAUTHORIZED
              value: "0"
            - name: APP_PORT
              value: "3000"
"""
    parser = YamlParser()
    items = parser.parse_string(yaml_content, "deployment.yaml")

    assert len(items) == 2
    keys = {item.key: item.value for item in items}
    assert keys["NODE_TLS_REJECT_UNAUTHORIZED"] == "0"
    assert keys["APP_PORT"] == "3000"


def test_parse_generic_yaml(tmp_path: Path) -> None:
    yaml_file = tmp_path / "settings.yaml"
    yaml_file.write_text("database:\n  host: 127.0.0.1\n  port: 5432\n", encoding="utf-8")

    parser = YamlParser()
    items = parser.parse_file(yaml_file)

    assert len(items) == 2
    keys = {item.key: item.value for item in items}
    assert keys["host"] == "127.0.0.1"
    assert keys["port"] == "5432"


def test_parse_invalid_yaml() -> None:
    invalid_content = "::: invalid yaml content :::"
    parser = YamlParser()
    items = parser.parse_string(invalid_content, "bad.yaml")
    assert items == []
