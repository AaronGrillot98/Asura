from app.services.scanner_registry import CORE_SCANNER_IDS
from app.services.tool_registry import load_arsenal


RECON_RUNNER_IDS = (
    "subfinder",
    "amass",
    "httpx",
    "naabu",
    "dnsx",
    "katana",
    "gau",
    "waybackurls",
    "hakrawler",
    "webanalyze",
    "whatweb",
    "wafw00f",
    "tlsx",
    "shuffledns",
    "assetfinder",
)

PASSIVE_RECON_IDS = {"subfinder", "amass", "gau", "waybackurls", "assetfinder"}
ACTIVE_RECON_IDS = set(RECON_RUNNER_IDS) - PASSIVE_RECON_IDS


def test_step_four_recon_tools_are_registered_in_priority_order() -> None:
    arsenal = load_arsenal()
    tools = {tool.id: tool for tool in arsenal.tools if tool.id in RECON_RUNNER_IDS}

    assert tuple(tools) == RECON_RUNNER_IDS
    assert all(tool.pack == "Recon Pack" for tool in tools.values())
    assert all(tool.execution == "optional_pack" for tool in tools.values())
    assert all(tool.integration_status == "runner" for tool in tools.values())


def test_recon_tools_do_not_expand_default_core_engine() -> None:
    assert set(RECON_RUNNER_IDS).isdisjoint(CORE_SCANNER_IDS)


def test_passive_recon_does_not_require_authorized_scope() -> None:
    arsenal = load_arsenal()
    tools = {tool.id: tool for tool in arsenal.tools if tool.id in PASSIVE_RECON_IDS}

    assert set(tools) == PASSIVE_RECON_IDS
    assert all([mode.value for mode in tool.modes] == ["passive"] for tool in tools.values())
    assert all(tool.safe_default for tool in tools.values())
    assert all(not tool.requires_authorized_scope for tool in tools.values())


def test_active_recon_requires_scope_and_has_risk_warnings() -> None:
    arsenal = load_arsenal()
    tools = {tool.id: tool for tool in arsenal.tools if tool.id in ACTIVE_RECON_IDS}

    assert set(tools) == ACTIVE_RECON_IDS
    assert all(any(mode.value in {"active", "lab"} for mode in tool.modes) for tool in tools.values())
    assert all(tool.requires_authorized_scope for tool in tools.values())
    assert all(tool.risk_warning for tool in tools.values())


def test_recon_tools_are_parser_backed() -> None:
    arsenal = load_arsenal()
    tools = [tool for tool in arsenal.tools if tool.id in RECON_RUNNER_IDS]

    assert all(tool.parser for tool in tools)
    assert all(tool.output_formats for tool in tools)
    assert all(tool.commands for tool in tools)

