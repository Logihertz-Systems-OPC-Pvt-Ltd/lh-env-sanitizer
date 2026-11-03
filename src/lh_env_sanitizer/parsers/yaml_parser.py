# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.parsers.yaml_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parser for Docker Compose and Kubernetes ConfigMap YAML configurations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from lh_env_sanitizer.models import EnvItem, SourceType
from lh_env_sanitizer.parsers.base import BaseParser


class _LineLoader(yaml.SafeLoader):
    """Safe YAML loader that preserves line numbers of keys."""


def _mapping_constructor(loader: _LineLoader, node: yaml.MappingNode) -> dict[str, Any]:
    """Construct mapping and attach __line__ annotations."""
    mapping: dict[str, Any] = {}
    lines: dict[str, int] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        val = loader.construct_object(value_node, deep=False)
        if isinstance(key, (str, int, float, bool)):
            key_str = str(key)
            mapping[key_str] = val
            lines[key_str] = key_node.start_mark.line + 1

    mapping["__lines__"] = lines
    return mapping


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping_constructor)


class YamlParser(BaseParser):
    """Parses YAML documents including Docker Compose and Kubernetes manifests."""

    def parse_file(self, file_path: Path) -> list[EnvItem]:
        # --- Multi-Format Parsing & Normalization Engine ---
        # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
        # applies fallback decoders, recovers from malformed lines, and standardizes
        # raw configuration attributes into typed domain model instances.
        """Parse configuration items from a YAML file.

        Args:
            file_path: Path to the YAML file.

        Returns:
            List of parsed EnvItem instances.
        """
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return self.parse_string(content, source_name=str(file_path))

    def parse_string(self, content: str, source_name: str) -> list[EnvItem]:
        """Parse configuration items from a YAML string.

        Args:
            content: Raw YAML content.
            source_name: Name or path of the source file.

        Returns:
            List of parsed EnvItem instances.
        """
        items: list[EnvItem] = []
        try:
            documents = list(yaml.load_all(content, Loader=_LineLoader))
        except yaml.YAMLError:
            # Fallback to standard safe_load_all if custom loader fails
            try:
                documents = list(yaml.safe_load_all(content))
            except yaml.YAMLError:
                return items

        for doc in documents:
            if not isinstance(doc, dict):
                continue

            # 1. Kubernetes ConfigMap or Workload
            kind = doc.get("kind")
            if isinstance(kind, str):
                items.extend(self._parse_kubernetes_doc(doc, source_name))
                continue

            # 2. Docker Compose
            services = doc.get("services")
            if isinstance(services, dict):
                items.extend(self._parse_compose_doc(doc, source_name))
                continue

            # 3. Generic YAML fallback
            items.extend(self._parse_generic_yaml(doc, source_name))

        return items

    def _parse_kubernetes_doc(self, doc: dict[str, Any], source_name: str) -> list[EnvItem]:
        """Extract environment variables and configuration from Kubernetes resources."""
        items: list[EnvItem] = []
        kind = str(doc.get("kind", ""))
        metadata = doc.get("metadata", {})
        meta_name = metadata.get("name", "unknown") if isinstance(metadata, dict) else "unknown"
        namespace = (
            metadata.get("namespace", "default") if isinstance(metadata, dict) else "default"
        )

        if kind.lower() == "configmap":
            data_blocks = [("data", doc.get("data")), ("binaryData", doc.get("binaryData"))]
            lines = doc.get("__lines__", {})
            for block_name, block in data_blocks:
                if not isinstance(block, dict):
                    continue
                block_lines = block.get("__lines__", {})
                for k, v in block.items():
                    if k == "__lines__":
                        continue
                    line_no = block_lines.get(k, lines.get(block_name))
                    items.append(
                        EnvItem(
                            key=str(k),
                            value=str(v) if v is not None else "",
                            source=source_name,
                            source_type=SourceType.K8S_CONFIGMAP,
                            line_number=line_no,
                            context={
                                "kind": "ConfigMap",
                                "name": meta_name,
                                "namespace": namespace,
                                "block": block_name,
                            },
                        )
                    )
            return items

        # Workload objects (Deployment, Pod, StatefulSet, DaemonSet, Job)
        # Search containers for env
        containers = self._extract_k8s_containers(doc)
        for container in containers:
            c_name = container.get("name", "container")
            env_list = container.get("env")
            if isinstance(env_list, list):
                for env_entry in env_list:
                    if isinstance(env_entry, dict) and "name" in env_entry:
                        k = env_entry["name"]
                        v = env_entry.get("value", "")
                        lines = env_entry.get("__lines__", {})
                        items.append(
                            EnvItem(
                                key=str(k),
                                value=str(v) if v is not None else "",
                                source=source_name,
                                source_type=SourceType.YAML,
                                line_number=lines.get("name"),
                                context={
                                    "kind": kind,
                                    "resource_name": meta_name,
                                    "container": c_name,
                                },
                            )
                        )
        return items

    def _extract_k8s_containers(self, doc: dict[str, Any]) -> list[dict[str, Any]]:
        """Find container definitions within a Kubernetes workload document."""
        containers: list[dict[str, Any]] = []
        spec = doc.get("spec", {})
        if not isinstance(spec, dict):
            return containers

        # Check direct spec.containers (Pod)
        direct_containers = spec.get("containers")
        if isinstance(direct_containers, list):
            containers.extend([c for c in direct_containers if isinstance(c, dict)])

        # Check spec.template.spec.containers (Deployment, ReplicaSet, etc.)
        template = spec.get("template", {})
        if isinstance(template, dict):
            pod_spec = template.get("spec", {})
            if isinstance(pod_spec, dict):
                t_containers = pod_spec.get("containers")
                if isinstance(t_containers, list):
                    containers.extend([c for c in t_containers if isinstance(c, dict)])

        return containers

    def _parse_compose_doc(self, doc: dict[str, Any], source_name: str) -> list[EnvItem]:
        """Extract environment variables from Docker Compose services."""
        items: list[EnvItem] = []
        services = doc.get("services", {})

        for service_name, s_def in services.items():
            if service_name == "__lines__" or not isinstance(s_def, dict):
                continue

            service_lines = s_def.get("__lines__", {})
            env_section = s_def.get("environment")

            # Environment as dictionary
            if isinstance(env_section, dict):
                env_lines = env_section.get("__lines__", {})
                for k, v in env_section.items():
                    if k == "__lines__":
                        continue
                    line_no = env_lines.get(k, service_lines.get("environment"))
                    items.append(
                        EnvItem(
                            key=str(k),
                            value=str(v) if v is not None else "",
                            source=source_name,
                            source_type=SourceType.DOCKER_COMPOSE,
                            line_number=line_no,
                            context={"service": service_name},
                        )
                    )

            # Environment as list of strings: ["KEY=VALUE", "KEY"]
            elif isinstance(env_section, list):
                env_line_fallback = service_lines.get("environment")
                for entry in env_section:
                    if isinstance(entry, str):
                        parts = entry.split("=", 1)
                        k = parts[0].strip()
                        v = parts[1].strip() if len(parts) > 1 else ""
                        items.append(
                            EnvItem(
                                key=k,
                                value=v,
                                source=source_name,
                                source_type=SourceType.DOCKER_COMPOSE,
                                line_number=env_line_fallback,
                                context={"service": service_name},
                            )
                        )

        return items

    def _parse_generic_yaml(self, doc: dict[str, Any], source_name: str) -> list[EnvItem]:
        """Traverse generic YAML hierarchies for key-value configuration pairs."""
        items: list[EnvItem] = []

        def _walk(node: Any, path: list[str]) -> None:
            if isinstance(node, dict):
                lines = node.get("__lines__", {})
                for k, v in node.items():
                    if k == "__lines__":
                        continue
                    if isinstance(v, (str, int, float, bool)) or v is None:
                        items.append(
                            EnvItem(
                                key=str(k),
                                value=str(v) if v is not None else "",
                                source=source_name,
                                source_type=SourceType.YAML,
                                line_number=lines.get(k),
                                context={"path": ".".join([*path, str(k)])},
                            )
                        )
                    elif isinstance(v, dict):
                        _walk(v, [*path, str(k)])

        _walk(doc, [])
        return items
