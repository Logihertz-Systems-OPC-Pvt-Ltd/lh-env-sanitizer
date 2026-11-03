# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.exporters.base
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Base exporter interface for audit findings."""

from __future__ import annotations

from abc import ABC, abstractmethod

from lh_env_sanitizer.models import AuditResult


class BaseExporter(ABC):
    """Abstract base class for formatting and exporting audit results."""

    @abstractmethod
    def export(self, result: AuditResult) -> str:
        """Format an AuditResult into the target presentation format.

        Args:
            result: The audit result containing findings and scan metadata.

        Returns:
            Formatted string output.
        """
