from datetime import datetime, timezone

from app.models.schemas import Project, ScanMode, ScopeRules, Target, ToolDefinition
from app.repositories.base import InMemoryRepository
from app.security.scope_guard import decide_scope


PROJECT = Project(
    id="p",
    workspace_id="w",
    name="Scope Tests",
    description="Test fixtures for scope decisions.",
    scope_rules=ScopeRules(
        domains=["example.com"],
        urls=["https://example.com"],
        cidrs=["10.0.0.0/24"],
        repos=[],
        containers=[],
        blocked_targets=[],
        allow_active=True,
        allow_lab=False,
    ),
    risk_score=50,
    targets=["https://example.com"],
    created_at=datetime(2026, 5, 16, tzinfo=timezone.utc),
)


def _audit_repo():
    return InMemoryRepository()


def test_passive_in_scope_decision_is_allowed() -> None:
    decision = decide_scope(
        project=PROJECT,
        target="https://example.com",
        mode=ScanMode.passive,
        explicit_authorization=False,
    )
    assert decision.allowed is True
    assert decision.reason_code == "passive_in_scope"


def test_active_requires_authorization() -> None:
    audit = _audit_repo()
    decision = decide_scope(
        project=PROJECT,
        target="https://example.com",
        mode=ScanMode.active,
        explicit_authorization=False,
        audit_repo=audit,
    )
    assert decision.allowed is False
    assert decision.reason_code == "active_requires_authorization"
    assert decision.audit_log_id is not None
    assert audit.count() == 1


def test_private_ip_requires_owned_internal_target() -> None:
    audit = _audit_repo()
    project = PROJECT.model_copy(update={
        "scope_rules": PROJECT.scope_rules.model_copy(update={"cidrs": ["192.168.0.0/16"]}),
    })
    decision = decide_scope(
        project=project,
        target="192.168.10.5",
        mode=ScanMode.active,
        explicit_authorization=True,
        audit_repo=audit,
    )
    assert decision.allowed is False
    assert decision.reason_code == "private_ip_not_marked_internal"

    target = Target(
        id="t", project_id="p", kind="ip", value="192.168.10.5",
        authorized=True, owned_internal=True,
    )
    decision2 = decide_scope(
        project=project,
        target="192.168.10.5",
        mode=ScanMode.active,
        explicit_authorization=True,
        target_record=target,
    )
    assert decision2.allowed is True
    assert decision2.reason_code == "active_in_scope"


def test_high_risk_tool_outside_allowlist_requires_lab() -> None:
    tool = ToolDefinition(
        id="velociraptor",
        name="Velociraptor",
        pack="DFIR Pack",
        category="endpoint dfir",
        execution="optional_pack",
        modes=[ScanMode.active],
        install_status="not_installed",
        integration_status="planned",
        license="AGPL-3.0",
        official_url="https://docs.velociraptor.app/",
        requires_authorized_scope=True,
        risk_level="restricted",
        recommended_use="restricted",
    )
    decision = decide_scope(
        project=PROJECT,
        target="https://example.com",
        mode=ScanMode.active,
        explicit_authorization=True,
        tool=tool,
    )
    assert decision.allowed is False
    assert decision.reason_code == "high_risk_requires_lab_mode"


def test_high_noise_warning_requires_confirmation() -> None:
    tool = ToolDefinition(
        id="ffuf",
        name="ffuf",
        pack="Web App Security Pack",
        category="web fuzzing",
        execution="optional_pack",
        modes=[ScanMode.active],
        install_status="not_installed",
        integration_status="planned",
        license="MIT",
        official_url="https://github.com/ffuf/ffuf",
        requires_authorized_scope=True,
        risk_level="medium",
        recommended_use="fuzzer",
    )
    decision = decide_scope(
        project=PROJECT,
        target="https://example.com",
        mode=ScanMode.active,
        explicit_authorization=True,
        tool=tool,
    )
    assert decision.allowed is False
    assert decision.requires_explicit_high_noise_confirm is True

    confirmed = decide_scope(
        project=PROJECT,
        target="https://example.com",
        mode=ScanMode.active,
        explicit_authorization=True,
        tool=tool,
        confirm_high_noise=True,
    )
    assert confirmed.allowed is True


def test_audit_log_records_block_decision() -> None:
    audit = _audit_repo()
    decide_scope(
        project=PROJECT,
        target="https://evil.example",
        mode=ScanMode.active,
        explicit_authorization=True,
        audit_repo=audit,
    )
    rows = audit.list()
    assert len(rows) == 1
    assert rows[0].decision == "block"
    assert rows[0].reason_code == "active_target_out_of_scope"
