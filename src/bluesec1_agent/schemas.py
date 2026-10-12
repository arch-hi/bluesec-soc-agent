import copy
from typing import Any

DROP_KEYS = {"$defs", "discriminator", "title", "additionalProperties", "default", "format"}
MAX_DEPTH = 20
# длинные enum часть провайдеров не принимает, переносим их в описание
LONG_ENUM = 30


def simplify_schema(schema: dict[str, Any]) -> dict[str, Any]:
    # не все провайдеры понимают ref, oneOf и const, сервер всё равно проверяет по полной схеме
    definitions = schema.get("$defs", {})

    def walk(node: Any, depth: int) -> Any:
        if depth > MAX_DEPTH:
            return {"type": "object"}
        if isinstance(node, list):
            return [walk(item, depth + 1) for item in node]
        if not isinstance(node, dict):
            return node
        if "$ref" in node:
            name = node["$ref"].rsplit("/", 1)[-1]
            merged = {**copy.deepcopy(definitions.get(name, {})), **node}
            merged.pop("$ref")
            return walk(merged, depth + 1)

        result: dict[str, Any] = {}
        for key, value in node.items():
            if key in DROP_KEYS:
                continue
            if key == "const":
                result["enum"] = [value]
            elif key == "oneOf":
                result["anyOf"] = walk(value, depth + 1)
            else:
                result[key] = walk(value, depth + 1)

        enum = result.get("enum")
        if isinstance(enum, list) and len(enum) > LONG_ENUM:
            del result["enum"]
            allowed = "One of: " + ", ".join(str(value) for value in enum) + "."
            description = result.get("description", "")
            result["description"] = f"{description} {allowed}".strip()

        if "anyOf" in result:
            options = [item for item in result.pop("anyOf") if item.get("type") != "null"]
            if len(options) == 1:
                result.update(options[0])
            else:
                result["anyOf"] = options
        return result

    return walk(schema, 0)


def simplify_tool(tool: dict[str, Any]) -> dict[str, Any]:
    function = tool["function"]
    return {
        "type": "function",
        "function": {
            "name": function["name"],
            "description": function.get("description", ""),
            "parameters": simplify_schema(function.get("parameters", {"type": "object"})),
        },
    }


def argument_problems(parameters: dict[str, Any], arguments: dict[str, Any]) -> list[str]:
    # только то, за что сервер точно отклонит вызов, anyOf оставляем серверу
    return _problems(simplify_schema(parameters), arguments, "")


def _problems(schema: Any, value: Any, path: str) -> list[str]:
    if not isinstance(schema, dict) or "anyOf" in schema:
        return []
    name = path or "arguments"
    problems: list[str] = []
    kind = schema.get("type")
    if kind == "object" and isinstance(value, dict):
        for key in schema.get("required") or []:
            if key not in value:
                problems.append(f"{_join(path, key)}: required field is missing")
        for key, child in (schema.get("properties") or {}).items():
            if key in value:
                problems.extend(_problems(child, value[key], _join(path, key)))
    elif kind == "string" and isinstance(value, str):
        minimum = schema.get("minLength")
        if isinstance(minimum, int) and len(value) < minimum:
            problems.append(f"{name}: needs at least {minimum} characters, got {len(value)}")
        allowed = schema.get("enum")
        if isinstance(allowed, list) and value not in allowed:
            problems.append(f"{name}: must be one of {allowed}")
    elif kind == "array" and isinstance(value, list):
        for index, item in enumerate(value):
            problems.extend(_problems(schema.get("items"), item, f"{name}[{index}]"))
    return problems


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key
