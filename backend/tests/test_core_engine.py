from app.services.runner import build_command, run_scanner, validate_target
from app.services.scanner_registry import (
    CORE_SCANNER_IDS,
    CORE_SCANNERS,
    SCANNERS,
    scanner_allowed,
)
from app.services.tool_registry import load_arsenal


def test_first_ten_core_scanners_are_locked() -> None:
    """`CORE_SCANNERS` is the contractual locked-10 view; SCANNERS is the
    wider runtime dispatch surface that grew as tools were promoted."""
    assert tuple(CORE_SCANNERS.keys()) == CORE_SCANNER_IDS
    assert set(CORE_SCANNER_IDS).issubset(set(SCANNERS.keys()))


def test_core_scanners_are_in_arsenal_as_core_runners() -> None:
    arsenal = load_arsenal()
    core_tools = {tool.id: tool for tool in arsenal.tools if tool.id in CORE_SCANNER_IDS}

    assert set(core_tools) == set(CORE_SCANNER_IDS)
    assert all(tool.execution == "core_runner" for tool in core_tools.values())
    assert all(tool.integration_status == "runner" for tool in core_tools.values())


def test_core_scanners_have_parser_and_output_metadata() -> None:
    for scanner in CORE_SCANNERS.values():
        assert scanner.parser
        assert scanner.output_format in {"json", "jsonl", "xml"}


def test_mode_gating_keeps_nmap_out_of_passive_mode() -> None:
    assert scanner_allowed("nmap", "passive") is False
    assert scanner_allowed("nmap", "active") is True


def test_command_builder_uses_mode_specific_templates() -> None:
    assert build_command("nmap", "10.10.7.20", "active") == [
        "nmap",
        "-sV",
        "--version-light",
        "-oX",
        "-",
        "10.10.7.20",
    ]
    assert build_command("checkov", "repo", "passive") == ["checkov", "-d", "repo", "-o", "json"]
    assert build_command("syft", "image:latest", "passive") == ["syft", "image:latest", "-o", "json"]
    assert build_command("grype", "sbom.json", "passive") == ["grype", "sbom.json", "-o", "json"]


def test_core_commands_are_generated_from_registry() -> None:
    arsenal = load_arsenal()
    nmap = next(tool for tool in arsenal.tools if tool.id == "nmap")
    registry_command = next(command.command for command in nmap.commands if command.mode == "active")

    assert " ".join(build_command("nmap", "10.10.7.20", "active")) == registry_command.replace("{{target}}", "10.10.7.20")


def test_active_core_scan_requires_authorization() -> None:
    run = run_scanner(
        project_id="demo",
        scanner="zap",
        target="https://demo.asura.local",
        mode="active",
        authorized=False,
    )

    assert run.status == "blocked"
    assert "explicit authorization" in run.message


def test_target_validation_blocks_option_injection_and_control_characters() -> None:
    assert validate_target("-oX bad") == "Target cannot start with a command option prefix."
    assert validate_target("example.com\nother") == "Target contains control characters."
    assert validate_target("https://example.com") is None
