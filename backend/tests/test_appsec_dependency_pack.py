from app.services.scanner_registry import CORE_SCANNER_IDS
from app.services.tool_registry import load_arsenal


APPSEC_DEPENDENCY_RUNNER_IDS = (
    "codeql",
    "bandit",
    "pip-audit",
    "npm-audit",
    "cargo-audit",
    "govulncheck",
    "gosec",
    "brakeman",
    "eslint-security",
    "bearer",
)


def test_step_three_tools_are_registered_as_runners() -> None:
    arsenal = load_arsenal()
    tools = {tool.id: tool for tool in arsenal.tools if tool.id in APPSEC_DEPENDENCY_RUNNER_IDS}

    assert tuple(tools) == APPSEC_DEPENDENCY_RUNNER_IDS
    assert all(tool.integration_status == "runner" for tool in tools.values())
    assert all(tool.execution == "optional_pack" for tool in tools.values())


def test_step_three_does_not_expand_default_core_engine() -> None:
    assert set(APPSEC_DEPENDENCY_RUNNER_IDS).isdisjoint(CORE_SCANNER_IDS)


def test_appsec_dependency_runners_are_passive_and_parser_backed() -> None:
    arsenal = load_arsenal()
    tools = [tool for tool in arsenal.tools if tool.id in APPSEC_DEPENDENCY_RUNNER_IDS]

    assert all([mode.value for mode in tool.modes] == ["passive"] for tool in tools)
    assert all(tool.safe_default for tool in tools)
    assert all(not tool.requires_authorized_scope for tool in tools)
    assert all(tool.parser for tool in tools)
    assert all(tool.output_formats for tool in tools)
    assert all(tool.commands for tool in tools)


def test_dependency_tools_cover_major_language_ecosystems() -> None:
    arsenal = load_arsenal()
    tools = {tool.id: tool for tool in arsenal.tools if tool.id in APPSEC_DEPENDENCY_RUNNER_IDS}

    assert "Python Dependencies Pack" == tools["pip-audit"].pack
    assert "JS Dependencies Pack" == tools["npm-audit"].pack
    assert "Rust Dependencies Pack" == tools["cargo-audit"].pack
    assert "Go Dependencies Pack" == tools["govulncheck"].pack

