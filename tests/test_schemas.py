from bluesec1_agent.schemas import argument_problems, simplify_schema, simplify_tool

SCHEMA = {
    "$defs": {
        "Benign": {
            "title": "Benign",
            "type": "object",
            "additionalProperties": False,
            "properties": {"verdict": {"const": "benign", "type": "string"}},
        },
        "Malicious": {
            "type": "object",
            "properties": {"verdict": {"const": "malicious", "type": "string"}},
        },
    },
    "type": "object",
    "properties": {
        "submission": {
            "discriminator": {"propertyName": "verdict"},
            "oneOf": [{"$ref": "#/$defs/Malicious"}, {"$ref": "#/$defs/Benign"}],
        },
        "page": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None},
    },
}


def test_simplify_schema_inlines_refs_and_drops_unsupported_features() -> None:
    result = simplify_schema(SCHEMA)

    assert "$defs" not in result
    submission = result["properties"]["submission"]
    assert "discriminator" not in submission
    assert [option["properties"]["verdict"] for option in submission["anyOf"]] == [
        {"enum": ["malicious"], "type": "string"},
        {"enum": ["benign"], "type": "string"},
    ]
    assert "additionalProperties" not in submission["anyOf"][1]
    assert result["properties"]["page"] == {"type": "integer"}


def test_simplify_tool_drops_strict_and_keeps_name() -> None:
    tool = {
        "type": "function",
        "function": {"name": "finish", "description": "d", "parameters": SCHEMA, "strict": True},
    }

    result = simplify_tool(tool)

    assert result["function"]["name"] == "finish"
    assert "strict" not in result["function"]
    assert "$defs" not in result["function"]["parameters"]


def test_long_enum_moves_into_description() -> None:
    values = [f"type_{number}" for number in range(40)]
    schema = {
        "type": "object",
        "properties": {
            "type": {"description": "Entity type.", "enum": values, "type": "string"},
            "kind": {"enum": ["entity", "relation"], "type": "string"},
        },
    }
    simplified = simplify_schema(schema)
    long_field = simplified["properties"]["type"]

    assert "enum" not in long_field
    assert long_field["description"].startswith("Entity type. One of: type_0, type_1")
    assert "type_39" in long_field["description"]
    assert simplified["properties"]["kind"]["enum"] == ["entity", "relation"]


SEARCH = {
    "type": "object",
    "required": ["query", "reasoning"],
    "properties": {
        "query": {"type": "string", "minLength": 5},
        "reasoning": {"type": "string", "minLength": 1},
        "sort_order": {"type": "string", "enum": ["ascending", "descending"]},
        "time_window": {
            "type": "object",
            "required": ["from", "to"],
            "properties": {"from": {"type": "string"}, "to": {"type": "string"}},
        },
        "scope": {"anyOf": [{"type": "object"}, {"type": "object"}]},
    },
}


def test_argument_problems_catch_short_query_and_missing_fields() -> None:
    problems = argument_problems(SEARCH, {"query": "3700", "time_window": {"from": "x"}})

    assert any("query" in problem and "5 characters" in problem for problem in problems)
    assert any(problem.startswith("reasoning") for problem in problems)
    assert any(problem.startswith("time_window.to") for problem in problems)


def test_argument_problems_accept_valid_call_and_skip_alternatives() -> None:
    arguments = {"query": "support.ps1", "reasoning": "r", "scope": {"kind": "x"}}

    assert argument_problems(SEARCH, arguments) == []
    assert argument_problems(SEARCH, {**arguments, "sort_order": "sideways"}) != []
