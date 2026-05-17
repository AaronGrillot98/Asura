from dataclasses import dataclass
import shlex

from app.models.schemas import ScanMode, ToolDefinition
from app.services.tool_registry import load_arsenal


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
        output_format=tool.output_formats[0],
        parser=tool.parser or "",
        description=tool.recommended_use,
    )


def load_core_scanners() -> dict[str, ScannerDefinition]:
    arsenal = load_arsenal()
    tools_by_id = {tool.id: tool for tool in arsenal.tools}
    return {tool_id: build_scanner_definition(tools_by_id[tool_id]) for tool_id in CORE_SCANNER_IDS}


SCANNERS: dict[str, ScannerDefinition] = load_core_scanners()


def scanner_allowed(scanner: str, mode: str) -> bool:
    definition = SCANNERS[scanner]
    return {
        "passive": definition.passive_allowed,
        "active": definition.active_allowed,
        "lab": definition.lab_allowed,
    }[mode]
