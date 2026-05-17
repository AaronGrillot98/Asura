from app.models.schemas import ToolDefinition
from app.services.tool_registry import load_contract_report, validate_contract


def test_registry_contract_is_valid() -> None:
    report = load_contract_report()

    assert report.valid is True
    assert report.errors == []
    assert len(report.registry_hash) == 64
    assert report.contract_version
    assert report.core_runner_count >= 10
    assert report.executable_count > 0
    assert report.blocked_count > 0


def test_blocked_tools_cannot_define_commands() -> None:
    blocked_tool = ToolDefinition(
        id="bad-blocked",
        name="Bad Blocked",
        pack="Blocked Tools",
        category="blocked",
        execution="blocked",
        modes=["lab"],
        install_status="blocked",
        integration_status="blocked",
        license="Not applicable",
        official_url="https://example.invalid",
        executable="bad",
        commands=[{"mode": "lab", "command": "bad {{target}}"}],
        recommended_use="Not supported.",
        risk_warning="Blocked.",
    )

    report = validate_contract([blocked_tool], ["policy"])

    assert report.valid is False
    assert any("blocked tools cannot define commands" in error for error in report.errors)
    assert any("blocked tools cannot define executable modes" in error for error in report.errors)
    assert any("blocked tools cannot define an executable" in error for error in report.errors)


def test_runner_tools_need_commands_for_every_mode() -> None:
    runner = ToolDefinition(
        id="partial-runner",
        name="Partial Runner",
        pack="Test Pack",
        category="test",
        execution="core_runner",
        modes=["passive", "active"],
        install_status="not_installed",
        integration_status="runner",
        license="MIT",
        official_url="https://example.invalid",
        executable="partial",
        input_types=["url"],
        output_formats=["json"],
        parser="partial_json",
        safe_default=True,
        requires_authorized_scope=True,
        docker_available=True,
        supported_os=["linux"],
        commands=[{"mode": "passive", "command": "partial {{target}}"}],
        recommended_use="Exercise contract validation.",
    )

    report = validate_contract([runner], ["policy"])

    assert report.valid is False
    assert any("runner tools need command templates for every mode" in error for error in report.errors)


def test_non_safe_active_tools_require_authorized_scope() -> None:
    runner = ToolDefinition(
        id="unsafe-runner",
        name="Unsafe Runner",
        pack="Test Pack",
        category="test",
        execution="optional_pack",
        modes=["active"],
        install_status="not_installed",
        integration_status="planned",
        license="MIT",
        official_url="https://example.invalid",
        executable="unsafe",
        input_types=["url"],
        output_formats=["json"],
        parser="unsafe_json",
        safe_default=False,
        requires_authorized_scope=False,
        docker_available=True,
        supported_os=["linux"],
        commands=[{"mode": "active", "command": "unsafe {{target}}"}],
        recommended_use="Exercise authorization validation.",
    )

    report = validate_contract([runner], ["policy"])

    assert report.valid is False
    assert any("non-safe active/lab tools must require authorized scope" in error for error in report.errors)


def test_unknown_command_placeholders_are_rejected() -> None:
    runner = ToolDefinition(
        id="bad-placeholder",
        name="Bad Placeholder",
        pack="Test Pack",
        category="test",
        execution="optional_pack",
        modes=["passive"],
        install_status="not_installed",
        integration_status="planned",
        license="MIT",
        official_url="https://example.invalid",
        executable="bad-placeholder",
        input_types=["url"],
        output_formats=["json"],
        parser="bad_json",
        safe_default=True,
        requires_authorized_scope=False,
        docker_available=True,
        supported_os=["linux"],
        commands=[{"mode": "passive", "command": "bad-placeholder {{untrusted}}"}],
        recommended_use="Exercise placeholder validation.",
    )

    report = validate_contract([runner], ["policy"])

    assert report.valid is False
    assert any("unsupported placeholders" in error for error in report.errors)


def test_executable_commands_must_use_declared_placeholders() -> None:
    runner = ToolDefinition(
        id="static-command",
        name="Static Command",
        pack="Test Pack",
        category="test",
        execution="optional_pack",
        modes=["passive"],
        install_status="not_installed",
        integration_status="planned",
        license="MIT",
        official_url="https://example.invalid",
        executable="static-command",
        input_types=["url"],
        output_formats=["json"],
        parser="static_json",
        safe_default=True,
        requires_authorized_scope=False,
        docker_available=True,
        supported_os=["linux"],
        commands=[{"mode": "passive", "command": "static-command --version"}],
        recommended_use="Exercise static command validation.",
    )

    report = validate_contract([runner], ["policy"])

    assert report.valid is False
    assert any("executable command must contain at least one declared placeholder" in error for error in report.errors)
