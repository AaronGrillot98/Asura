"""Scope enforcement service.

Every scanner runner calls into this module before executing. Rules:

- Passive scans must target a project-listed or scope-rule-matching target.
- Active scans require explicit authorization AND scope-rule match.
- Lab scans require lab mode enabled on the project (and on the target if one
  is registered) AND explicit authorization.
- Private / loopback / link-local addresses cannot be actively scanned unless
  the target is marked `owned_internal`.
- High-risk tools (`risk_level` in {"high", "restricted"}) require lab mode
  unless explicitly allow-listed for authorized active use.
- Every decision (allow OR block) writes one audit log row when an audit repo
  is supplied.
- Returns a structured `ScopeDecision`. A back-compat helper preserves the
  legacy `str | None` API used by older callers and tests.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Iterable, Optional
from urllib.parse import urlparse

from app.models.schemas import (
    AuditLog,
    Project,
    ScanMode,
    ScopeDecision,
    Target,
    ToolDefinition,
)
from app.security.private_networks import is_private_ip

# Tools whose `risk_level` is `high`/`restricted` but which we still allow in
# AUTHORIZED_ACTIVE_MODE against in-scope targets. Anything outside this list
# at those risk levels must run in LAB_VALIDATION_MODE.
_HIGH_RISK_AUTH_ACTIVE_ALLOWLIST: frozenset[str] = frozenset(
    {"nuclei", "zap", "ffuf", "feroxbuster", "nikto"}
)

# Tools whose default mode is high-noise. We surface a warning so the API
# caller can present the operator with a confirmation step.
_HIGH_NOISE_TOOLS: frozenset[str] = frozenset(
    {"ffuf", "feroxbuster", "gobuster", "nikto", "kiterunner", "naabu", "amass"}
)


def normalize_target(target: str) -> str:
    return target.strip()


def target_in_scope(project: Project, target: str) -> bool:
    target = normalize_target(target)
    rules = project.scope_rules
    if target in rules.blocked_targets:
        return False
    if target in rules.repos or target in rules.containers or target in rules.urls:
        return True
    parsed = urlparse(target)
    hostname = parsed.hostname or target.split("/")[0]
    if hostname in rules.domains:
        return True
    if any(hostname == domain or hostname.endswith(f".{domain}") for domain in rules.domains):
        return True
    try:
        candidate = ip_address(hostname)
        return any(candidate in ip_network(cidr, strict=False) for cidr in rules.cidrs)
    except ValueError:
        return False


def _decision(
    *,
    allowed: bool,
    reason_code: str,
    reason: Optional[str],
    target: str,
    mode: ScanMode,
    audit_repo=None,
    actor: str = "demo-user",
    workspace_id: Optional[str] = None,
    tool_id: Optional[str] = None,
    requires_explicit_high_noise_confirm: bool = False,
) -> ScopeDecision:
    audit_log_id: Optional[str] = None
    if audit_repo is not None:
        audit_log_id = f"audit-{uuid.uuid4().hex[:12]}"
        audit_repo.add(
            AuditLog(
                id=audit_log_id,
                workspace_id=workspace_id,
                actor=actor,
                action=f"scope.{'allow' if allowed else 'block'}",
                event_type="scope_decision",
                target=target,
                result="allow" if allowed else "block",
                decision="allow" if allowed else "block",
                reason=reason,
                reason_code=reason_code,
                payload={
                    "mode": mode.value if isinstance(mode, ScanMode) else str(mode),
                    "tool_id": tool_id,
                    "requires_high_noise_confirm": requires_explicit_high_noise_confirm,
                },
                timestamp=datetime.now(timezone.utc),
            )
        )
    return ScopeDecision(
        allowed=allowed,
        reason=reason,
        reason_code=reason_code,
        audit_log_id=audit_log_id,
        requires_explicit_high_noise_confirm=requires_explicit_high_noise_confirm,
        target=target,
        mode=mode,
    )


def decide_scope(
    *,
    project: Project,
    target: str,
    mode: ScanMode,
    explicit_authorization: bool,
    target_record: Optional[Target] = None,
    tool: Optional[ToolDefinition] = None,
    confirm_high_noise: bool = False,
    audit_repo=None,
    actor: str = "demo-user",
) -> ScopeDecision:
    """Return a structured scope decision plus an audit log entry."""
    target = normalize_target(target)
    workspace_id = getattr(project, "workspace_id", None)
    tool_id = tool.id if tool is not None else None

    # ---- mode validation ---------------------------------------------
    if mode == ScanMode.passive:
        if target_in_scope(project, target) or target in project.targets:
            return _decision(
                allowed=True,
                reason_code="passive_in_scope",
                reason=None,
                target=target,
                mode=mode,
                audit_repo=audit_repo,
                actor=actor,
                workspace_id=workspace_id,
                tool_id=tool_id,
            )
        return _decision(
            allowed=False,
            reason_code="passive_target_out_of_scope",
            reason="Passive scan target is not listed in project scope.",
            target=target,
            mode=mode,
            audit_repo=audit_repo,
            actor=actor,
            workspace_id=workspace_id,
            tool_id=tool_id,
        )

    if mode == ScanMode.active:
        if not project.scope_rules.allow_active:
            return _decision(
                allowed=False,
                reason_code="active_disabled_for_project",
                reason="Project scope does not allow active scans.",
                target=target,
                mode=mode,
                audit_repo=audit_repo,
                actor=actor,
                workspace_id=workspace_id,
                tool_id=tool_id,
            )
        if not explicit_authorization:
            return _decision(
                allowed=False,
                reason_code="active_requires_authorization",
                reason="Active scans require explicit authorization.",
                target=target,
                mode=mode,
                audit_repo=audit_repo,
                actor=actor,
                workspace_id=workspace_id,
                tool_id=tool_id,
            )
        if not target_in_scope(project, target):
            return _decision(
                allowed=False,
                reason_code="active_target_out_of_scope",
                reason="Active scan target is outside the project allowlist.",
                target=target,
                mode=mode,
                audit_repo=audit_repo,
                actor=actor,
                workspace_id=workspace_id,
                tool_id=tool_id,
            )
        # Private-IP guard.
        if is_private_ip(target) and (target_record is None or not target_record.owned_internal):
            return _decision(
                allowed=False,
                reason_code="private_ip_not_marked_internal",
                reason="Private / loopback addresses require Target.owned_internal=True.",
                target=target,
                mode=mode,
                audit_repo=audit_repo,
                actor=actor,
                workspace_id=workspace_id,
                tool_id=tool_id,
            )
        # High-risk tool gate.
        if tool is not None and tool.risk_level in {"high", "restricted"} and tool.id not in _HIGH_RISK_AUTH_ACTIVE_ALLOWLIST:
            return _decision(
                allowed=False,
                reason_code="high_risk_requires_lab_mode",
                reason=f"Tool '{tool.id}' has risk_level={tool.risk_level} and requires LAB_VALIDATION_MODE.",
                target=target,
                mode=mode,
                audit_repo=audit_repo,
                actor=actor,
                workspace_id=workspace_id,
                tool_id=tool_id,
            )
        requires_noise_confirm = bool(
            tool is not None
            and tool.id in _HIGH_NOISE_TOOLS
            and not confirm_high_noise
        )
        return _decision(
            allowed=not requires_noise_confirm,
            reason_code="active_in_scope" if not requires_noise_confirm else "high_noise_confirmation_required",
            reason=None if not requires_noise_confirm else "High-noise scan requires explicit confirmation.",
            target=target,
            mode=mode,
            audit_repo=audit_repo,
            actor=actor,
            workspace_id=workspace_id,
            tool_id=tool_id,
            requires_explicit_high_noise_confirm=requires_noise_confirm,
        )

    if mode == ScanMode.lab:
        if not project.scope_rules.allow_lab:
            return _decision(
                allowed=False,
                reason_code="lab_disabled_for_project",
                reason="Lab mode is disabled for this project.",
                target=target,
                mode=mode,
                audit_repo=audit_repo,
                actor=actor,
                workspace_id=workspace_id,
                tool_id=tool_id,
            )
        if not explicit_authorization:
            return _decision(
                allowed=False,
                reason_code="lab_requires_authorization",
                reason="Lab scans require explicit authorization.",
                target=target,
                mode=mode,
                audit_repo=audit_repo,
                actor=actor,
                workspace_id=workspace_id,
                tool_id=tool_id,
            )
        if not target_in_scope(project, target):
            return _decision(
                allowed=False,
                reason_code="lab_target_out_of_scope",
                reason="Lab scan target is outside the project allowlist.",
                target=target,
                mode=mode,
                audit_repo=audit_repo,
                actor=actor,
                workspace_id=workspace_id,
                tool_id=tool_id,
            )
        if target_record is not None and not target_record.lab_mode_enabled:
            return _decision(
                allowed=False,
                reason_code="target_lab_mode_disabled",
                reason="Target.lab_mode_enabled must be True for lab scans.",
                target=target,
                mode=mode,
                audit_repo=audit_repo,
                actor=actor,
                workspace_id=workspace_id,
                tool_id=tool_id,
            )
        return _decision(
            allowed=True,
            reason_code="lab_in_scope",
            reason=None,
            target=target,
            mode=mode,
            audit_repo=audit_repo,
            actor=actor,
            workspace_id=workspace_id,
            tool_id=tool_id,
        )

    return _decision(
        allowed=False,
        reason_code="unsupported_mode",
        reason="Unsupported scan mode.",
        target=target,
        mode=mode,
        audit_repo=audit_repo,
        actor=actor,
        workspace_id=workspace_id,
        tool_id=tool_id,
    )


def validate_scan_scope(
    project: Project,
    target: str,
    mode: ScanMode,
    explicit_authorization: bool,
) -> str | None:
    """Back-compat helper used by the existing API route and tests.

    Returns None when the scan is allowed, or the textual reason if blocked.
    New code should call `decide_scope()` instead.
    """
    decision = decide_scope(
        project=project,
        target=target,
        mode=mode,
        explicit_authorization=explicit_authorization,
    )
    if decision.allowed:
        return None
    return decision.reason or decision.reason_code


def high_risk_authorized_active_allowlist() -> Iterable[str]:
    """Exposed for tests/docs so the allowlist is auditable."""
    return tuple(sorted(_HIGH_RISK_AUTH_ACTIVE_ALLOWLIST))


def high_noise_tools() -> Iterable[str]:
    return tuple(sorted(_HIGH_NOISE_TOOLS))
