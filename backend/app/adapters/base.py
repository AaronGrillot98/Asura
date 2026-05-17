from dataclasses import dataclass

from app.models.schemas import ScanMode, ToolDefinition


@dataclass(frozen=True)
class AdapterPlan:
    tool_id: str
    mode: ScanMode
    command: list[str]
    parser: str
    output_format: str
    scaffolded: bool


class ToolAdapter:
    def __init__(self, tool: ToolDefinition) -> None:
        self.tool = tool

    @property
    def scaffolded(self) -> bool:
        return self.tool.integration_status != "runner"

    def plan(self, target: str, mode: ScanMode) -> AdapterPlan:
        command = next((entry.command for entry in self.tool.commands if entry.mode == mode), None)
        if command is None:
            raise ValueError(f"{self.tool.id} does not support {mode.value} mode")
        return AdapterPlan(
            tool_id=self.tool.id,
            mode=mode,
            command=[part.replace("{{target}}", target) for part in command.split()],
            parser=self.tool.parser or "unparsed",
            output_format=self.tool.output_formats[0] if self.tool.output_formats else "text",
            scaffolded=self.scaffolded,
        )

