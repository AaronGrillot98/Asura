"""Legacy agents shim.

The original CorrelationAgent / RemediationAgent / ScopeGuardAgent classes
have been collapsed into `app.services.pentest_brain.PentestBrain`. This
module re-exports thin wrappers so any external import path keeps working.
"""
from __future__ import annotations

from app.models.schemas import AgentOutput, Confidence, Finding


class _BaseDelegate:
    name: str = "agent"

    def analyze(self, findings: list[Finding]) -> AgentOutput:  # pragma: no cover - shim
        return AgentOutput(
            agent=self.name,
            summary="Use app.services.pentest_brain.PentestBrain for evidence-grounded reasoning.",
            confidence=Confidence.medium,
            cited_evidence_ids=[],
        )


class CorrelationAgent(_BaseDelegate):
    name = "correlation_agent"


class RemediationAgent(_BaseDelegate):
    name = "remediation_agent"


class ScopeGuardAgent(_BaseDelegate):
    name = "scope_guard_agent"


__all__ = ["CorrelationAgent", "RemediationAgent", "ScopeGuardAgent"]
