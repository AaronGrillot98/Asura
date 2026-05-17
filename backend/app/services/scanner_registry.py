from dataclasses import dataclass
import shlex

from app.models.schemas import ScanMode, ToolDefinition
from app.services.tool_registry import load_arsenal


# The 10 first-class engines locked by the contract. Listed here so other
# parts of the codebase can refer to "core" without scanning the registry.
CORE_SCANNER_IDS = (
    "nmap",
    "nuclei",
    "semgrep",
    "trivy",
    "gitleaks",
    "osv-scanner",
    "checkov",
    "zap",
    "syft",
    "grype",
)


@dataclass(frozen=True)
class ScannerDefinition:
    name: str
    executable: str
    commands: dict[str, list[str]]
    passive_allowed: bool
    active_allowed: bool
    lab_allowed: bool
    output_format: str
    parser: str
    description: str


def command_to_args(command: str) -> list[str]:
    return shlex.split(command)


def build_scanner_definition(tool: ToolDefinition) -> ScannerDefinition:
    commands = {command.mode.value: command_to_args(command.command) for command in tool.commands}
    return ScannerDefinition(
        name=tool.id,
        executable=tool.executable or tool.id,
        commands=commands,
        passive_allowed=ScanMode.passive in tool.modes,
        active_allowed=ScanMode.active in tool.modes,
        lab_allowed=ScanMode.lab in tool.modes,
        output_format=tool.output_formats[0] if tool.output_formats else "text",
        parser=tool.parser or "",
        description=tool.recommended_use,
    )


def load_core_scanners() -> dict[str, ScannerDefinition]:
    """The locked first-10 view. Used by the /api/scanners endpoint as a
    contractual surface so the core engines are pinned across releases."""
    arsenal = load_arsenal()
    tools_by_id = {tool.id: tool for tool in arsenal.tools}
    return {tool_id: build_scanner_definition(tools_by_id[tool_id]) for tool_id in CORE_SCANNER_IDS}


def load_runner_scanners() -> dict[str, ScannerDefinition]:
    """Every tool with `integration_status: runner` is dispatch-ready.

    Includes the 10 core engines AND every other tool that has been
    promoted to runner status (slice 2 AppSec pack, slice 10 fuzzers +
    K8s/cloud, etc.). Tools at `planned` / `reference` / `analyzer` /
    `importer` / `blocked` are excluded — they show in the Arsenal page
    but are not runnable.
    """
    arsenal = load_arsenal()
    return {
        tool.id: build_scanner_definition(tool)
        for tool in arsenal.tools
        if tool.integration_status == "runner"
        and tool.commands
        and tool.executable
    }


# Contract-locked core 10. Other modules import this for the "first-class
# engines" semantics — tests pin against it.
CORE_SCANNERS: dict[str, ScannerDefinition] = load_core_scanners()

# Runtime dispatch surface — every scanner the runner can spawn today.
SCANNERS: dict[str, ScannerDefinition] = load_runner_scanners()


def scanner_allowed(scanner: str, mode: str) -> bool:
    if scanner not in SCANNERS:
        return False
    definition = SCANNERS[scanner]
    return {
        "passive": definition.passive_allowed,
        "active": definition.active_allowed,
        "lab": definition.lab_allowed,
    }[mode]
