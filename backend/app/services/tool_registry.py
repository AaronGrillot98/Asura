from functools import lru_cache
import hashlib
from pathlib import Path
import re
from shutil import which
from typing import Any

import yaml

from app.models.schemas import ArsenalSummary, RegistryContractReport, ToolDefinition, ToolPackSummary
from app.security.blocked_capabilities import labels as blocked_capability_labels

REGISTRY_PATH = Path(__file__).resolve().parents[2] / "registry" / "tools.yaml"
CONTRACT_VERSION = "2026-05-17.3"
ALLOWED_COMMAND_VARIABLES = {"target", "wordlist", "database", "provider", "rules", "model_type", "resolver_list"}
PLACEHOLDER_PATTERN = re.compile(r"{{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*}}")
EXECUTABLE_EXECUTIONS = {"core_runner", "optional_pack"}
NON_EXECUTABLE_EXECUTIONS = {"reference", "blocked", "importer", "analyzer"}


@lru_cache
def load_arsenal() -> ArsenalSummary:
    with REGISTRY_PATH.open("r", encoding="utf-8") as handle:
        document: dict[str, Any] = yaml.safe_load(handle)

    tools = [with_install_state(ToolDefinition.model_validate(tool)) for tool in document["tools"]]
    report = validate_contract(tools, document.get("blocked_policy", []))
    if not report.valid:
        raise ValueError("Invalid tool registry contract: " + "; ".join(report.errors))
    packs = sorted({tool.pack for tool in tools})
    return ArsenalSummary(
        tools=tools,
        packs=packs,
        pack_summaries=[summarize_pack(pack, tools) for pack in packs],
        blocked_policy=document.get("blocked_policy", []),
        blocked_capabilities=blocked_capability_labels(),
    )


def load_contract_report() -> RegistryContractReport:
    with REGISTRY_PATH.open("r", encoding="utf-8") as handle:
        document: dict[str, Any] = yaml.safe_load(handle)
    tools = [ToolDefinition.model_validate(tool) for tool in document["tools"]]
    return validate_contract(tools, document.get("blocked_policy", []))


def registry_hash() -> str:
    return hashlib.sha256(REGISTRY_PATH.read_bytes()).hexdigest()


def with_install_state(tool: ToolDefinition) -> ToolDefinition:
    installed = bool(tool.executable and which(tool.executable))
    return tool.model_copy(update={"installed": installed})


def summarize_pack(pack: str, tools: list[ToolDefinition]) -> ToolPackSummary:
    pack_tools = [tool for tool in tools if tool.pack == pack]
    return ToolPackSummary(
        name=pack,
        total=len(pack_tools),
        core_runners=sum(tool.execution == "core_runner" for tool in pack_tools),
        optional=sum(tool.execution == "optional_pack" for tool in pack_tools),
        reference=sum(tool.execution == "reference" for tool in pack_tools),
        blocked=sum(tool.execution == "blocked" for tool in pack_tools),
        installed=sum(tool.installed for tool in pack_tools),
    )


def validate_contract(tools: list[ToolDefinition], blocked_policy: list[str]) -> RegistryContractReport:
    errors: list[str] = []
    ids = [tool.id for tool in tools]
    duplicate_ids = sorted({tool_id for tool_id in ids if ids.count(tool_id) > 1})
    for tool_id in duplicate_ids:
        errors.append(f"{tool_id}: duplicate tool id")

    if not blocked_policy:
        errors.append("blocked_policy: at least one policy statement is required")

    for tool in tools:
        errors.extend(validate_tool(tool))

    return RegistryContractReport(
        valid=not errors,
        errors=errors,
        registry_hash=registry_hash(),
        contract_version=CONTRACT_VERSION,
        tool_count=len(tools),
        core_runner_count=sum(tool.execution == "core_runner" for tool in tools),
        optional_count=sum(tool.execution == "optional_pack" for tool in tools),
        reference_count=sum(tool.execution == "reference" for tool in tools),
        executable_count=sum(tool.execution in {"core_runner", "optional_pack"} for tool in tools),
        blocked_count=sum(tool.execution == "blocked" for tool in tools),
    )


def validate_tool(tool: ToolDefinition) -> list[str]:
    errors: list[str] = []
    prefix = f"{tool.id}:"

    if tool.id != tool.id.lower() or " " in tool.id:
        errors.append(f"{prefix} id must be lowercase and space-free")
    if not tool.name.strip():
        errors.append(f"{prefix} name is required")
    if not tool.pack.strip():
        errors.append(f"{prefix} pack is required")
    if not tool.category.strip():
        errors.append(f"{prefix} category is required")
    if not tool.recommended_use.strip():
        errors.append(f"{prefix} recommended_use is required")
    if not tool.official_url.startswith(("https://", "http://")):
        errors.append(f"{prefix} official_url must be absolute")

    command_modes = [command.mode for command in tool.commands]
    unknown_command_modes = [mode.value for mode in command_modes if mode not in tool.modes]
    if unknown_command_modes:
        errors.append(f"{prefix} command modes must be declared in modes: {', '.join(unknown_command_modes)}")

    for command in tool.commands:
        if not command.command.strip():
            errors.append(f"{prefix} command template cannot be empty")
        variables = set(PLACEHOLDER_PATTERN.findall(command.command))
        unknown_variables = sorted(variables - ALLOWED_COMMAND_VARIABLES)
        if unknown_variables:
            errors.append(f"{prefix} command has unsupported placeholders: {', '.join(unknown_variables)}")
        if tool.execution in {"core_runner", "optional_pack"} and not variables:
            errors.append(f"{prefix} executable command must contain at least one declared placeholder")
        if command.command.strip().startswith(("sudo ", "rm ", "del ", "powershell ", "cmd ")):
            errors.append(f"{prefix} command template starts with a disallowed launcher or destructive command")

    if tool.execution == "blocked":
        if tool.commands:
            errors.append(f"{prefix} blocked tools cannot define commands")
        if tool.modes:
            errors.append(f"{prefix} blocked tools cannot define executable modes")
        if tool.executable:
            errors.append(f"{prefix} blocked tools cannot define an executable")
        if tool.install_status != "blocked" or tool.integration_status != "blocked":
            errors.append(f"{prefix} blocked tools must use blocked statuses")
        if not tool.risk_warning:
            errors.append(f"{prefix} blocked tools require a risk warning")
        return errors

    if tool.execution == "reference":
        if tool.commands:
            errors.append(f"{prefix} reference tools cannot define commands")
        if tool.integration_status != "reference":
            errors.append(f"{prefix} reference tools must use reference integration_status")
        if tool.install_status not in {"external", "available", "not_installed"}:
            errors.append(f"{prefix} reference tools cannot use install_status {tool.install_status}")
        return errors

    if tool.execution == "importer":
        if tool.commands:
            errors.append(f"{prefix} importer tools cannot define commands")
        if tool.integration_status not in {"importer", "planned"}:
            errors.append(f"{prefix} importer tools must use importer or planned integration_status")
        return errors

    if tool.execution == "analyzer":
        if tool.commands:
            errors.append(f"{prefix} analyzer tools cannot define commands")
        if tool.integration_status not in {"analyzer", "planned", "reference"}:
            errors.append(f"{prefix} analyzer tools must use analyzer/planned/reference integration_status")
        return errors

    if not tool.modes:
        errors.append(f"{prefix} executable tools must declare at least one mode")
    if tool.integration_status == "planned" and not tool.commands:
        # Catalog-only planned entry. Skip the executable-requirement block; if
        # a planned tool later gains command templates, full validation kicks
        # in for those commands via the per-command loop above.
        return errors
    if not tool.commands:
        errors.append(f"{prefix} executable tools must define command templates")
    if not tool.executable:
        errors.append(f"{prefix} executable tools must define executable")
    if not tool.parser:
        errors.append(f"{prefix} executable tools must declare parser")
    if not tool.output_formats:
        errors.append(f"{prefix} executable tools must declare output_formats")
    if not tool.input_types:
        errors.append(f"{prefix} executable tools must declare input_types")
    if not tool.supported_os:
        errors.append(f"{prefix} executable tools must declare supported_os")

    touches_target = any(mode.value in {"active", "lab"} for mode in tool.modes)
    if touches_target and not tool.safe_default and not tool.requires_authorized_scope:
        errors.append(f"{prefix} non-safe active/lab tools must require authorized scope")

    if tool.integration_status == "runner":
        declared_modes = set(tool.modes)
        command_mode_set = set(command_modes)
        missing_modes = sorted(mode.value for mode in declared_modes - command_mode_set)
        if missing_modes:
            errors.append(f"{prefix} runner tools need command templates for every mode: {', '.join(missing_modes)}")

    return errors


def query_arsenal(
    search: str | None = None,
    pack: str | None = None,
    execution: str | None = None,
    risk: str | None = None,
    tag: str | None = None,
    lab_only: bool | None = None,
    installed: bool | None = None,
) -> ArsenalSummary:
    arsenal = load_arsenal()
    tools = arsenal.tools
    if search:
        needle = search.lower()
        tools = [
            tool
            for tool in tools
            if needle in tool.name.lower()
            or needle in tool.category.lower()
            or needle in tool.pack.lower()
            or needle in tool.recommended_use.lower()
            or any(needle in t.lower() for t in tool.tags)
        ]
    if pack:
        tools = [tool for tool in tools if tool.pack == pack]
    if execution:
        tools = [tool for tool in tools if tool.execution == execution]
    if risk:
        tools = [tool for tool in tools if tool.risk_level == risk]
    if tag:
        needle = tag.lower()
        tools = [tool for tool in tools if any(t.lower() == needle for t in tool.tags)]
    if lab_only is not None:
        tools = [tool for tool in tools if tool.requires_lab_mode == lab_only]
    if installed is not None:
        tools = [tool for tool in tools if tool.installed == installed]
    packs = sorted({tool.pack for tool in tools})
    return ArsenalSummary(
        tools=tools,
        packs=packs,
        pack_summaries=[summarize_pack(pack_name, tools) for pack_name in packs],
        blocked_policy=arsenal.blocked_policy,
        blocked_capabilities=blocked_capability_labels(),
    )
