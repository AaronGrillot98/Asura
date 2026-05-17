from app.adapters.base import ToolAdapter
from app.services.tool_registry import load_arsenal


def get_adapter(tool_id: str) -> ToolAdapter | None:
    arsenal = load_arsenal()
    tool = next((item for item in arsenal.tools if item.id == tool_id), None)
    if tool is None or tool.execution in {"blocked", "reference"}:
        return None
    return ToolAdapter(tool)

