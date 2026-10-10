"""Generate the typed management clients from the OpenAPI documents Cbox ID publishes.

The specs are vendored in ``openapi/``; the output is ``src/cbox_id/management/generated/``.

    python -m scripts.generate_management              regenerate from openapi/*.yaml
    python -m scripts.generate_management --fetch environment=https://acme.cboxid.com
                                                       refresh one vendored spec from a live host
    python -m scripts.generate_management --fetch all=https://id.example.com
                                                       refresh all four from one (self-hosted) host
    python -m scripts.generate_management --check      exit 1 when the generated code is stale

A small generator on purpose: the output is meant to be read. It knows exactly the subset of
JSON Schema the server's spec builder emits, and fails loudly on anything it does not
understand rather than guessing. The Python twin of id-js's ``scripts/generate-management.ts``.
"""

from __future__ import annotations

import argparse
import builtins
import json
import keyword
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
SPEC_DIR = ROOT / "openapi"
OUT_DIR = ROOT / "src" / "cbox_id" / "management" / "generated"

Json = dict[str, Any]


@dataclass(frozen=True)
class PlaneConfig:
    plane: str
    module: str
    class_name: str
    #: Path the server serves this spec at, relative to the host.
    spec_path: str
    #: Security schemes that are this plane's management credentials.
    schemes: tuple[str, ...]
    #: Path prefix stripped when a non-action route's name is derived from its path.
    prefix: str


PLANES: tuple[PlaneConfig, ...] = (
    PlaneConfig(
        plane="environment",
        module="environment",
        class_name="EnvironmentClient",
        spec_path="/api/v1/environment/openapi.yaml",
        schemes=("EnvironmentApiKey", "ManagementAccessToken", "WorkspaceAccessToken"),
        prefix="",
    ),
    PlaneConfig(
        plane="workspace",
        module="workspace",
        class_name="WorkspaceClient",
        spec_path="/api/v1/workspace/openapi.yaml",
        schemes=("OrganizationApiKey", "WorkspaceApiKey", "WorkspaceAccessToken"),
        prefix="/workspace",
    ),
    PlaneConfig(
        plane="platform",
        module="platform",
        class_name="PlatformClient",
        spec_path="/api/v1/platform/openapi.yaml",
        schemes=("OperatorToken",),
        prefix="/platform",
    ),
    PlaneConfig(
        plane="account",
        module="account",
        class_name="AccountClient",
        spec_path="/api/v1/me/openapi.yaml",
        schemes=("PersonToken",),
        prefix="/me",
    ),
)

METHODS = ("get", "post", "put", "patch", "delete")
WRITES = frozenset({"POST", "PUT", "PATCH", "DELETE"})
DANGERS = frozenset({"read", "write", "destructive", "critical"})

#: What a generated module imports, by source. Only the names a module uses are imported.
IMPORTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("collections.abc", ("Iterator", "Mapping")),
    ("typing", ("Any", "Literal", "TypeAlias", "overload")),
    ("typing_extensions", ("NotRequired", "TypedDict")),
    ("..client", ("ManagementClient",)),
    ("..models", ("ApiResponse", "ApprovalMode", "OperationSpec", "PendingApprovalResult")),
    ("..transport", ("ManagementTransport",)),
)

#: Names a schema may not take as-is: they would shadow an import or a builtin.
RESERVED = {name for _, names in IMPORTS for name in names} | set(dir(builtins))

#: Members every client already has; a namespace may not take these names.
CLIENT_MEMBERS = frozenset({"core", "request", "close", "base_url"})

#: Parameter names a generated method already uses.
CALL_PARAMETERS = frozenset(
    {"self", "body", "query", "approval", "idempotency_key", "approval_id", "headers"}
)

#: Names a generated method signature refers to; a method may not shadow them in its class.
SIGNATURE_NAMES = frozenset(
    {"str", "None", "Mapping", "Literal", "Iterator", "ApiResponse", "PendingApprovalResult"}
    | {"ApprovalMode"}
)

SIMPLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
IDENTIFIER_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class GeneratorError(Exception):
    """The spec uses something this generator does not understand."""


class _SpecLoader(yaml.SafeLoader):
    """YAML 1.2 scalars: only ``true``/``false`` are booleans, and dates stay strings.

    PyYAML follows YAML 1.1, where an unquoted ``on``, ``no`` or ``2026-10-08`` would turn an
    enum value or an example into something the server never meant.
    """


_SpecLoader.yaml_implicit_resolvers = {
    first: [
        (tag, regexp)
        for tag, regexp in resolvers
        if tag not in ("tag:yaml.org,2002:bool", "tag:yaml.org,2002:timestamp")
    ]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_SpecLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


def load_spec(text: str) -> Json:
    parsed = yaml.load(text, Loader=_SpecLoader)  # noqa: S506 - a SafeLoader subclass

    if not isinstance(parsed, dict):
        raise GeneratorError("not a YAML mapping")

    return parsed


def obj(value: object) -> Json:
    return value if isinstance(value, dict) else {}


def arr(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def names_in(expression: str) -> set[str]:
    """The names a type expression refers to — not the words inside its string literals."""
    return set(IDENTIFIER_TOKEN.findall(re.sub(r'"(?:[^"\\]|\\.)*"', "", expression)))


def pascal(parts: Iterable[str]) -> str:
    out = ""

    for part in parts:
        for segment in re.split(r"[^A-Za-z0-9]+", part):
            if segment:
                out += segment[:1].upper() + segment[1:]

    return out


def identifier(name: str) -> str:
    """A Python identifier for a name from the spec: ``import`` → ``import_``."""
    out = re.sub(r"\W", "_", name)

    if out[:1].isdigit():
        out = f"_{out}"

    return f"{out}_" if keyword.iskeyword(out) else out


def literal(value: object) -> str:
    if isinstance(value, bool):
        return "True" if value else "False"

    if value is None:
        return "None"

    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)

    if isinstance(value, (int, float)):
        return repr(value)

    raise GeneratorError(f"unsupported literal {value!r}")


def _escape_doc(line: str) -> str:
    return line.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')


def docstring(text: str | None, indent: str, extra: Sequence[str] = ()) -> str:
    lines = [line.rstrip() for line in (text or "").strip().split("\n")]
    lines = [_escape_doc(line) for line in [*lines, *extra]]

    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()

    if not lines:
        return ""

    if len(lines) == 1 and not lines[0].endswith('"'):
        return f'{indent}"""{lines[0]}"""\n'

    body = "\n".join(f"{indent}{line}" if line else "" for line in lines[1:])
    rest = f"{body}\n" if body else ""

    return f'{indent}"""{lines[0]}\n{rest}{indent}"""\n'


def comment(text: str | None, indent: str) -> str:
    lines = [line.rstrip() for line in (text or "").strip().split("\n")]

    if lines == [""]:
        return ""

    return "".join(f"{indent}#: {line}".rstrip() + "\n" for line in lines)


@dataclass
class Operation:
    name: list[str]
    key: str
    action: str | None
    operation_id: str | None
    method: str
    path: str
    path_params: list[str]
    summary: str | None
    description: str | None
    scope: str | None
    danger: str | None
    approval: bool
    input_kind: str | None
    input_required: bool
    input_schema: Json | None
    response_schema: Json | None
    pagination: str | None


@dataclass
class _Node:
    children: dict[str, _Node] = field(default_factory=dict)
    ops: list[Operation] = field(default_factory=list)


class Generator:
    def __init__(self, spec: Json, config: PlaneConfig) -> None:
        self.spec = spec
        self.config = config
        self.blocks: list[str] = []
        self.used: set[str] = set()
        self.imports: set[str] = set()
        self.type_names: dict[str, str] = {}
        self.object_components: set[str] = set()
        self.generated_types: set[str] = set()
        self.skipped: list[str] = []

        for name, schema in self.schemas().items():
            safe = f"{name}Schema" if name in RESERVED else name

            if not SIMPLE_NAME.match(safe) or keyword.iskeyword(safe):
                raise GeneratorError(f"{config.module}: schema name {name!r} is not an identifier")

            self.type_names[name] = safe
            self.used.add(safe)
            self.generated_types.add(safe)

            if self._is_object(schema):
                self.object_components.add(name)

    # ── Spec access ──────────────────────────────────────────────────────────────────────

    def components(self, kind: str) -> Json:
        components = self.spec.get("components")
        section = components.get(kind) if isinstance(components, dict) else None
        return section if isinstance(section, dict) else {}

    def schemas(self) -> Json:
        return self.components("schemas")

    def deref(self, value: object, kind: str) -> Json:
        if isinstance(value, dict) and isinstance(value.get("$ref"), str):
            name = value["$ref"].split("/")[-1]
            target = self.components(kind).get(name)

            if not isinstance(target, dict):
                raise GeneratorError(f"{self.config.module}: unresolved {value['$ref']}")

            return target

        if not isinstance(value, dict):
            raise GeneratorError(f"{self.config.module}: expected an object, got {value!r}")

        return value

    def _is_object(self, schema: object) -> bool:
        if not isinstance(schema, dict):
            return False

        if "allOf" in schema:
            return True

        return bool(schema.get("properties")) and schema.get("type", "object") == "object"

    # ── Names ────────────────────────────────────────────────────────────────────────────

    def claim(self, name: str) -> str:
        if name in self.used or name in RESERVED:
            raise GeneratorError(f"{self.config.module}: generated name {name} collides")

        self.used.add(name)
        self.generated_types.add(name)
        return name

    def use(self, *names: str) -> None:
        self.imports.update(names)

    # ── Types ────────────────────────────────────────────────────────────────────────────

    def type_of(self, schema: object, hint: str) -> str:
        """A JSON Schema as a Python type expression; inline objects become named TypedDicts."""
        if schema is None or schema is True or schema == {}:
            self.use("Any")
            return "Any"

        if not isinstance(schema, dict):
            raise GeneratorError(f"{self.config.module}: unsupported schema {schema!r}")

        if isinstance(schema.get("$ref"), str):
            name = schema["$ref"].split("/")[-1]

            if name not in self.type_names:
                raise GeneratorError(f"{self.config.module}: unresolved {schema['$ref']}")

            return self.type_names[name]

        if "const" in schema:
            self.use("Literal")
            return f"Literal[{literal(schema['const'])}]"

        for key in ("oneOf", "anyOf"):
            if isinstance(schema.get(key), list):
                return self.union(
                    [self.type_of(s, f"{hint}Option{i + 1}") for i, s in enumerate(schema[key])]
                )

        if "allOf" in schema:
            name = self.claim(hint)
            self.typed_dict(name, schema)
            return name

        raw_type = schema.get("type")
        types: list[str] = (
            list(raw_type)
            if isinstance(raw_type, list)
            else [raw_type]
            if isinstance(raw_type, str)
            else []
        )

        if isinstance(schema.get("enum"), list):
            values = [literal(v) for v in schema["enum"] if v is not None]
            self.use("Literal")
            out = f"Literal[{', '.join(values)}]"
            nullable = "null" in types or None in schema["enum"]
            return f"{out} | None" if nullable else out

        if not types:
            if schema.get("properties"):
                return self.object_type(schema, hint)

            self.use("Any")
            return "Any"

        return self.union([self.primitive(t, schema, hint) for t in types])

    def union(self, parts: list[str]) -> str:
        unique = list(dict.fromkeys(parts))

        if "Any" in unique:
            return "Any"

        # `None` last reads as "optional".
        unique.sort(key=lambda part: part == "None")
        return " | ".join(unique)

    def primitive(self, kind: str, schema: Json, hint: str) -> str:
        if kind == "string":
            return "str"
        if kind == "integer":
            return "int"
        if kind == "number":
            return "float"
        if kind == "boolean":
            return "bool"
        if kind == "null":
            return "None"
        if kind == "array":
            return f"list[{self.type_of(schema.get('items'), f'{hint}Item')}]"
        if kind == "object":
            return self.object_type(schema, hint)

        raise GeneratorError(f"{self.config.module}: unsupported type {kind}")

    def object_type(self, schema: Json, hint: str) -> str:
        properties = schema.get("properties")
        additional = schema.get("additionalProperties")

        if not properties:
            if additional is None or additional is False or additional is True:
                self.use("Any")
                return "dict[str, Any]"

            return f"dict[str, {self.type_of(additional, f'{hint}Value')}]"

        name = self.claim(hint)
        self.typed_dict(name, schema)
        return name

    def typed_dict(self, name: str, schema: Json) -> None:
        """Emit a TypedDict for an object schema (or an ``allOf`` of them)."""
        bases: list[str] = []
        parts: list[Json] = [schema]

        if "allOf" in schema:
            parts = []

            for part in schema["allOf"]:
                if isinstance(part, dict) and isinstance(part.get("$ref"), str):
                    ref = part["$ref"].split("/")[-1]

                    if ref not in self.object_components:
                        raise GeneratorError(
                            f"{self.config.module}: {name} extends {ref}, which is not an object"
                        )

                    bases.append(self.type_names[ref])
                elif self._is_object(part) or (isinstance(part, dict) and "properties" in part):
                    parts.append(part)
                else:
                    raise GeneratorError(f"{self.config.module}: unsupported allOf part in {name}")

        if schema.get("properties") and schema.get("additionalProperties") not in (None, False):
            raise GeneratorError(
                f"{self.config.module}: {name} has both properties and additionalProperties"
            )

        fields: list[tuple[str, str, str | None]] = []

        for part in parts:
            required = set(part.get("required") or [])

            for key, value in (part.get("properties") or {}).items():
                annotation = self.type_of(value, f"{name}{pascal([key])}")

                if key not in required:
                    self.use("NotRequired")
                    annotation = f"NotRequired[{annotation}]"

                description = value.get("description") if isinstance(value, dict) else None
                fields.append((key, annotation, description))

        self.use("TypedDict")
        description = schema.get("description")
        tokens = {t for _, annotation, _ in fields for t in names_in(annotation)}
        functional = any(
            not SIMPLE_NAME.match(key) or keyword.iskeyword(key) or key in tokens
            for key, _, _ in fields
        )

        if functional:
            if bases:
                raise GeneratorError(f"{self.config.module}: {name} cannot be both")

            # Keys that are not identifiers, or that would shadow a type the class body uses.
            entries = ", ".join(f"{literal(k)}: {a!r}" for k, a, _ in fields)
            block = f'{name} = TypedDict("{name}", {{{entries}}})\n'
            self.blocks.append(f"{block}{docstring(description, '')}")
            return

        lines = [f"class {name}({', '.join(bases) if bases else 'TypedDict'}):"]
        doc = docstring(description, "    ")

        if doc:
            lines.append(doc.rstrip("\n"))

            if fields:
                lines.append("")

        for key, annotation, field_doc in fields:
            note = comment(field_doc, "    ")

            if note:
                # A described field gets air above it, so its comment reads as its own.
                if len(lines) > 1:
                    lines.append("")
                lines.append(note.rstrip("\n"))

            lines.append(f"    {key}: {annotation}")

        if len(lines) == 1:
            lines.append("    pass")

        self.blocks.append("\n".join(lines) + "\n")

    def alias(self, name: str, expression: str, description: str | None = None) -> None:
        self.use("TypeAlias")
        # Quoted only when it names a generated type, which may be defined further down.
        forward = names_in(expression) & self.generated_types
        value = repr(expression) if forward else expression
        self.blocks.append(f"{comment(description, '')}{name}: TypeAlias = {value}\n")

    def named(self, expression: str, name: str, description: str | None = None) -> str:
        """``expression`` when it already is a name; else a new alias ``name`` for it."""
        if expression in self.generated_types or expression in ("Any", "None"):
            return expression

        self.alias(self.claim(name), expression, description)
        return name

    # ── Operations ───────────────────────────────────────────────────────────────────────

    def operations(self) -> list[Operation]:
        paths = obj(self.spec.get("paths"))
        default_security = arr(self.spec.get("security"))
        ops: list[Operation] = []

        for path, raw_item in paths.items():
            item = self.deref(raw_item, "pathItems")
            shared = arr(item.get("parameters"))

            for method in METHODS:
                op = item.get(method)

                if not isinstance(op, dict):
                    continue

                security = arr(op["security"]) if "security" in op else default_security
                schemes = [name for entry in security if isinstance(entry, dict) for name in entry]
                action = text(op.get("x-action"))

                if not any(scheme in self.config.schemes for scheme in schemes):
                    listed = ", ".join(schemes) or "no security"
                    self.skipped.append(f"{method.upper()} {path} ({listed})")
                    continue

                own = arr(op.get("parameters"))
                parameters = [self.deref(p, "parameters") for p in [*shared, *own]]
                path_params = re.findall(r"\{([^}]+)\}", path)
                query = [p for p in parameters if p.get("in") == "query"]
                description = text(op.get("description"))
                # `x-scope` / `x-danger` are the contract. Routes the spec builder does not
                # generate from an action carry neither, and only say it in prose.
                scope = text(op.get("x-scope"))
                danger = text(op.get("x-danger"))

                if scope is None and description is not None:
                    found = re.search(r"Requires scope `([^`]+)`", description)
                    scope = found.group(1) if found else None

                if danger is None and description is not None:
                    found = re.search(r"Danger: ([a-z]+)", description)
                    danger = found.group(1) if found else None

                if danger is not None and danger not in DANGERS:
                    raise GeneratorError(
                        f"{self.config.module}: {method} {path} has an unknown danger {danger}"
                    )

                raw_responses = obj(op.get("responses"))
                responses = {str(code): value for code, value in raw_responses.items()}
                input_kind: str | None = None
                input_schema: Json | None = None
                input_required = False

                if op.get("requestBody") is not None:
                    body = self.deref(op["requestBody"], "requestBodies")
                    content = obj(body.get("content"))
                    json_body = content.get("application/json")

                    if not isinstance(json_body, dict):
                        raise GeneratorError(
                            f"{self.config.module}: {method} {path} has a non-JSON body"
                        )

                    if query:
                        raise GeneratorError(
                            f"{self.config.module}: {method} {path} has a body and a query"
                        )

                    input_kind = "body"
                    raw_schema = json_body.get("schema")
                    input_schema = raw_schema if isinstance(raw_schema, dict) else {}
                    required_props = len(input_schema.get("required") or [])
                    input_required = body.get("required") is True and required_props > 0
                elif query:
                    input_kind = "query"
                    properties: Json = {}

                    for param in query:
                        param_schema = obj(param.get("schema"))
                        if isinstance(param.get("description"), str):
                            param_schema = {**param_schema, "description": param["description"]}
                        properties[param["name"]] = param_schema

                    input_schema = {
                        "type": "object",
                        "properties": properties,
                        "required": [p["name"] for p in query if p.get("required") is True],
                    }
                    input_required = any(p.get("required") is True for p in query)

                response_schema: Json | None = None

                for code in ("200", "201", "204"):
                    if code not in responses:
                        continue

                    response = self.deref(responses[code], "responses")
                    content = obj(response.get("content"))
                    json_response = content.get("application/json")
                    schema = (
                        json_response.get("schema") if isinstance(json_response, dict) else None
                    )
                    response_schema = schema if isinstance(schema, dict) else None
                    break

                # An action whose own answer is `202 Accepted` documents it as `oneOf` its body
                # and the approval body. The branch that is not the approval is the result.
                if "202" in responses and not {"200", "201", "204"} & responses.keys():
                    accepted = self.deref(responses["202"], "responses")
                    accepted_json = obj(accepted.get("content")).get("application/json")
                    accepted_schema = (
                        obj(accepted_json.get("schema")) if isinstance(accepted_json, dict) else {}
                    )
                    own = [
                        branch
                        for branch in arr(accepted_schema.get("oneOf"))
                        if isinstance(branch, dict)
                        and "approval_required" not in json.dumps(branch)
                    ]
                    response_schema = own[0] if own else None

                query_names = {p.get("name") for p in query}
                name = action.split(".") if action is not None else self.derived_name(method, path)

                ops.append(
                    Operation(
                        name=name,
                        key=action if action is not None else ".".join(name),
                        action=action,
                        operation_id=op.get("operationId")
                        if isinstance(op.get("operationId"), str)
                        else None,
                        method=method.upper(),
                        path=path,
                        path_params=path_params,
                        summary=text(op.get("summary")),
                        description=description,
                        scope=scope,
                        danger=danger,
                        approval="202" in responses and self.is_approval(responses["202"]),
                        input_kind=input_kind,
                        input_required=input_required,
                        input_schema=input_schema,
                        response_schema=response_schema,
                        pagination="cursor"
                        if "after" in query_names
                        else "page"
                        if "page" in query_names
                        else None,
                    )
                )

        # The account and platform planes name every action `account.…` / `platform.…`. The
        # client already says which plane it is, so `me.sessions.revoke_others()` rather than
        # `me.account.sessions.revoke_others()`. Only when EVERY action shares the prefix.
        actions = [o for o in ops if o.action is not None]

        if actions and all(o.name[0] == self.config.plane and len(o.name) > 2 for o in actions):
            for o in actions:
                o.name = o.name[1:]

        for o in ops:
            o.name = [identifier(segment) for segment in o.name]

        return sorted(ops, key=lambda o: ".".join(o.name))

    def is_approval(self, response: object) -> bool:
        if isinstance(response, dict) and isinstance(response.get("$ref"), str):
            return bool(response["$ref"].endswith("/ApprovalRequired"))

        return "approval_required" in json.dumps(response)

    def derived_name(self, method: str, path: str) -> list[str]:
        """A name for a route that is not an action: ``GET /apis/{id}`` → ``apis.get``."""
        prefix = self.config.prefix
        rest = path[len(prefix) :] if prefix and path.startswith(f"{prefix}/") else path
        segments = [s for s in rest.split("/") if s]
        resources = [s.replace("-", "_") for s in segments if not s.startswith("{")]
        on_item = bool(segments) and segments[-1].startswith("{")
        verb = {
            "get": "get" if on_item else "list",
            "post": "create",
            "put": "set",
            "patch": "update",
            "delete": "delete",
        }[method]

        return [*resources, verb]

    # ── Rendering ────────────────────────────────────────────────────────────────────────

    def render(self) -> tuple[str, list[Operation]]:
        config = self.config
        info = obj(self.spec.get("info"))
        title = text(info.get("title")) or config.class_name
        operations = self.operations()
        table = f"{config.plane.upper()}_OPERATIONS"
        self.claim(table)
        self.claim(config.class_name)

        # ── Schemas
        self.blocks.append(f"# ── Schemas (components.schemas) {'─' * 66}\n")

        for name, schema in self.schemas().items():
            type_name = self.type_names[name]
            description = schema.get("description") if isinstance(schema, dict) else None

            if name in self.object_components:
                self.typed_dict(type_name, schema)
            else:
                expression = self.type_of(schema, f"{type_name}Value")
                self.alias(type_name, expression, description)

        # ── Per-operation types
        self.blocks.append(f"# ── Operation inputs and responses {'─' * 64}\n")
        signatures: dict[str, tuple[str | None, str, str | None]] = {}

        for op in operations:
            base = pascal(op.name)
            input_type: str | None = None

            if op.input_kind is not None and op.input_schema is not None:
                suffix = "Body" if op.input_kind == "body" else "Query"
                hint = f"{base}{suffix}"
                expression = self.type_of(op.input_schema, hint)
                input_type = expression if expression == hint else self.named(expression, hint)

            data_type, item_type = self.response_types(op, base)
            signatures[op.key] = (input_type, data_type, item_type)

        # ── Operation table
        self.blocks.append(f"# ── Operations {'─' * 84}\n")
        self.use("Mapping", "OperationSpec")
        keys = [op.key for op in operations]

        if len(set(keys)) != len(keys):
            raise GeneratorError(f"{config.module}: two operations share a key")

        rows = [comment(f"Every operation of the {title}, keyed by action name.", "").rstrip()]
        rows.append(f"{table}: Mapping[str, OperationSpec] = {{")

        for op in operations:
            params = ", ".join(literal(p) for p in op.path_params)
            path_params = f"({params},)" if len(op.path_params) == 1 else f"({params})"
            spec = ", ".join(
                [
                    f"action={literal(op.action)}",
                    f"operation_id={literal(op.operation_id)}",
                    f"method={literal(op.method)}",
                    f"path={literal(op.path)}",
                    f"path_params={path_params}",
                    f"scope={literal(op.scope)}",
                    f"danger={literal(op.danger)}",
                    f"approval={literal(op.approval)}",
                    f"body={literal(op.input_kind == 'body')}",
                    f"pagination={literal(op.pagination)}",
                ]
            )
            rows.append(f"    {literal(op.key)}: OperationSpec({spec}),")

        rows.append("}\n")
        self.blocks.append("\n".join(rows))

        # ── Namespaces
        self.blocks.append(f"# ── Namespaces {'─' * 84}\n")
        root = _Node()

        for op in operations:
            node = root

            for segment in op.name[:-1]:
                node = node.children.setdefault(segment, _Node())

            node.ops.append(op)

        if root.ops:
            names = ", ".join(".".join(o.name) for o in root.ops)
            raise GeneratorError(
                f"{config.module}: an operation has a single-segment name: {names}"
            )

        for segment in root.children:
            if segment in CLIENT_MEMBERS:
                raise GeneratorError(
                    f"{config.module}: namespace {segment} shadows a client member"
                )

        self.use("ManagementTransport")

        for path, node in self.walk(root, []):
            self.namespace(path, node, table, signatures)

        # ── Client
        self.blocks.append(f"# ── Client {'─' * 88}\n")
        self.use("ManagementClient")
        servers = arr(self.spec.get("servers"))
        fixed = next(
            (
                s["url"]
                for s in servers
                if isinstance(s, dict) and isinstance(s.get("url"), str) and "{" not in s["url"]
            ),
            None,
        )
        default_base = re.sub(r"/api/v1/?$", "", fixed) if fixed is not None else None
        raw_description = text(info.get("description")) or ""
        intro = raw_description.split("\n\n")[0]
        base_note = (
            f"``base_url`` defaults to ``{default_base}``."
            if default_base is not None
            else "``base_url`` is required: the environment's own host."
        )
        lines = [f"class {config.class_name}(ManagementClient):"]
        lines.append(docstring(f"{title}.\n\n{intro}\n\n{base_note}", "    ").rstrip("\n"))
        lines.append("")
        lines.append(f"    _plane = {literal(config.plane)}")

        if default_base is not None:
            lines.append(f"    _default_base_url = {literal(default_base)}")

        lines.append("")
        lines.append("    def _bind(self, core: ManagementTransport) -> None:")

        for segment in root.children:
            lines.append(f"        self.{segment} = {self.namespace_class([segment])}(core)")

        self.blocks.append("\n".join(lines) + "\n")

        header = (
            f"# GENERATED by scripts/generate_management.py from openapi/{config.module}.yaml"
            " — do not edit.\n"
            "# Regenerate with `python -m scripts.generate_management`.\n"
        )
        module_doc = f'"""{_escape_doc(title)}: typed client, schemas and operation table."""\n'
        imports = ["from __future__ import annotations", ""]
        group = ""

        for module, imported in IMPORTS:
            used = [n for n in imported if n in self.imports]

            if not used:
                continue

            # isort: stdlib, then third party, then local — a blank line between groups.
            kind = "local" if module.startswith(".") else "third" if "_" in module else "std"

            if group and kind != group:
                imports.append("")

            group = kind
            imports.append(f"from {module} import {', '.join(used)}")

        code = "\n".join([header + module_doc, *imports, "", ""]) + "\n\n".join(self.blocks)
        code = re.sub(r"\n{3,}", "\n\n\n", code).rstrip() + "\n"

        return code, operations

    def response_types(self, op: Operation, base: str) -> tuple[str, str | None]:
        """The type of ``data`` in the response, and of one item when the list is paged."""
        schema = op.response_schema

        if schema is None:
            return "None", None

        properties = obj(schema.get("properties"))
        data = properties.get("data") if "data" in properties else schema
        hint = f"{base}Data"
        item_type: str | None = None

        if isinstance(data, dict) and data.get("type") == "array":
            item = self.type_of(data.get("items"), f"{hint}Item")
            expression = f"list[{item}]"

            if op.pagination is not None:
                item_type = self.named(item, f"{base}Item")
        else:
            if op.pagination is not None:
                raise GeneratorError(f"{self.config.module}: paged {op.key} answers no data array")

            expression = self.type_of(data, hint)

        if expression == hint:
            return expression, item_type

        return self.named(expression, hint), item_type

    def walk(self, node: _Node, path: list[str]) -> list[tuple[list[str], _Node]]:
        """Every namespace below the root, children before their parent."""
        out: list[tuple[list[str], _Node]] = []

        for segment, child in node.children.items():
            out.extend(self.walk(child, [*path, segment]))
            out.append(([*path, segment], child))

        return out

    def namespace_class(self, path: list[str]) -> str:
        return f"{pascal(path)}Methods"

    def namespace(
        self,
        path: list[str],
        node: _Node,
        table: str,
        signatures: dict[str, tuple[str | None, str, str | None]],
    ) -> None:
        name = self.claim(self.namespace_class(path))
        members: set[str] = set()
        lines = [f"class {name}:"]
        lines.append(f'    """``{".".join(path)}.*``"""')
        lines.append("")
        lines.append("    def __init__(self, core: ManagementTransport) -> None:")
        lines.append("        self._core = core")

        for segment in node.children:
            members.add(segment)
            lines.append(f"        self.{segment} = {self.namespace_class([*path, segment])}(core)")

        def member(member_name: str, where: str) -> str:
            if (
                member_name in members
                or member_name.startswith("_")
                or member_name in SIGNATURE_NAMES
            ):
                raise GeneratorError(
                    f"{self.config.module}: member {member_name} collides at {where}"
                )

            if member_name in self.generated_types:
                raise GeneratorError(f"{self.config.module}: member {member_name} shadows a type")

            members.add(member_name)
            return member_name

        for op in node.ops:
            leaf = member(op.name[-1], ".".join(op.name))
            input_type, data_type, item_type = signatures[op.key]
            lines.append("")
            lines.extend(self.method(op, leaf, table, input_type, data_type))

            if op.pagination is not None and item_type is not None:
                all_name = member(f"{leaf}_all", ".".join(op.name) + "_all")
                lines.append("")
                lines.extend(self.paged_method(op, all_name, table, input_type, item_type))

        self.blocks.append("\n".join(lines) + "\n")

    def _parameters(self, op: Operation, input_type: str | None) -> tuple[list[str], list[str]]:
        params: list[str] = []
        args: list[str] = []

        for raw in op.path_params:
            param = identifier(raw)

            if param in CALL_PARAMETERS:
                raise GeneratorError(f"{self.config.module}: path parameter {raw} collides")

            params.append(f"{param}: str")
            args.append(param)

        if input_type is not None:
            arg = "body" if op.input_kind == "body" else "query"
            params.append(
                f"{arg}: {input_type}"
                if op.input_required
                else f"{arg}: {input_type} | None = None"
            )

        return params, args

    def method(
        self, op: Operation, leaf: str, table: str, input_type: str | None, data_type: str
    ) -> list[str]:
        params, args = self._parameters(op, input_type)
        write = op.method in WRITES
        path_args = f"({args[0]},)" if len(args) == 1 else f"({', '.join(args)})"
        input_arg = (
            "None" if input_type is None else ("body" if op.input_kind == "body" else "query")
        )
        response = f"ApiResponse[{data_type}]"
        self.use("ApiResponse", "Mapping")
        headers = "headers: Mapping[str, str] | None = None"
        key_param = "idempotency_key: str | None = None"
        meta = [f"``{op.method} {op.path}``" + (f" · action ``{op.action}``" if op.action else "")]

        if op.scope is not None or op.danger is not None:
            facts = []
            if op.scope is not None:
                facts.append(f"Scope ``{op.scope}``")
            if op.danger is not None:
                facts.append(f"danger: {op.danger}")
            meta.append(" · ".join(facts) + ".")

        if op.approval:
            meta.append(
                "May be held for approval (``202 approval_required``): waited on unless"
                ' ``approval="return"``.'
            )

        details = f"\n\n{op.description}" if op.description and op.description.strip() else ""
        doc = docstring(f"{op.summary or ''}{details}", "        ", ["", *meta])
        lines: list[str] = []

        if op.approval:
            self.use("overload", "Literal", "PendingApprovalResult", "ApprovalMode")
            pending = f"{response} | PendingApprovalResult[{data_type}]"
            shared = [key_param] if write else []
            shared += ["approval_id: str | None = None", headers]
            wait = ", ".join(["self", *params, "*", 'approval: Literal["wait"] = "wait"', *shared])
            give = ", ".join(["self", *params, "*", 'approval: Literal["return"]', *shared])
            impl = ", ".join(["self", *params, "*", 'approval: ApprovalMode = "wait"', *shared])
            call_kwargs = ["approval=approval"]
            call_kwargs += ["idempotency_key=idempotency_key"] if write else []
            call_kwargs += ["approval_id=approval_id", "headers=headers"]
            lines += [
                "    @overload",
                f"    def {leaf}({wait}) -> {response}: ...",
                "",
                "    @overload",
                f"    def {leaf}({give}) -> {pending}: ...",
                "",
                f"    def {leaf}({impl}) -> {pending}:",
            ]
        else:
            shared = [key_param] if write else []
            shared += [headers]
            signature = ", ".join(["self", *params, "*", *shared])
            call_kwargs = ["idempotency_key=idempotency_key"] if write else []
            call_kwargs += ["headers=headers"]
            lines.append(f"    def {leaf}({signature}) -> {response}:")

        lines.append(doc.rstrip("\n"))
        lines.append(
            f"        return self._core.call({table}[{literal(op.key)}], {path_args}, {input_arg},"
            f" {', '.join(call_kwargs)})"
        )

        return lines

    def paged_method(
        self, op: Operation, name: str, table: str, input_type: str | None, item_type: str
    ) -> list[str]:
        self.use("Iterator", "Mapping")
        params, args = self._parameters(op, None)
        query = f"query: {input_type} | None = None" if input_type is not None else None
        signature = ", ".join(
            [
                "self",
                *params,
                *([query] if query else []),
                "*",
                "headers: Mapping[str, str] | None = None",
            ]
        )
        path_args = f"({args[0]},)" if len(args) == 1 else f"({', '.join(args)})"
        query_arg = "query" if input_type is not None else "None"
        dotted = ".".join(op.name)
        doc = docstring(
            f"Every item of ``{dotted}``, fetching pages as the iteration reaches them.", "        "
        )

        return [
            f"    def {name}({signature}) -> Iterator[{item_type}]:",
            doc.rstrip("\n"),
            f"        return self._core.paginate({table}[{literal(op.key)}], {path_args},"
            f" {query_arg}, headers=headers)",
        ]


@dataclass(frozen=True)
class Result:
    code: str
    operations: int
    skipped: list[str]


def generate_plane(spec: Json, config: PlaneConfig) -> Result:
    """Generate one plane's client module from its parsed spec."""
    version = spec.get("openapi")

    if not isinstance(version, str) or not version.startswith("3."):
        raise GeneratorError(f"{config.module}: not an OpenAPI 3 document")

    generator = Generator(spec, config)
    code, operations = generator.render()

    return Result(code=code, operations=len(operations), skipped=generator.skipped)


def generate_all(root: Path = ROOT) -> dict[Path, Result]:
    """Generate every plane from the vendored specs in ``openapi/``, keyed by output path."""
    results: dict[Path, Result] = {}

    for config in PLANES:
        spec = load_spec((root / "openapi" / f"{config.module}.yaml").read_text("utf-8"))
        out = root / "src" / "cbox_id" / "management" / "generated" / f"{config.module}.py"
        results[out] = generate_plane(spec, config)

    return results


def fetch_spec(config: PlaneConfig, target: str) -> None:
    import httpx

    url = (
        target if target.endswith((".yaml", ".json")) else f"{target.rstrip('/')}{config.spec_path}"
    )
    response = httpx.get(url, headers={"Accept": "application/yaml, application/json"})

    if response.status_code != 200:
        raise GeneratorError(f"GET {url} answered {response.status_code}")

    parsed = load_spec(response.text)

    if not isinstance(parsed.get("openapi"), str):
        raise GeneratorError(f"GET {url} did not return an OpenAPI document")

    (SPEC_DIR / f"{config.module}.yaml").write_text(response.text, "utf-8")
    print(f"fetched {config.module} <- {url}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scripts.generate_management")
    parser.add_argument("--check", action="store_true", help="exit 1 when generated code is stale")
    parser.add_argument(
        "--fetch",
        action="append",
        default=[],
        metavar="PLANE=URL",
        help="refresh a vendored spec from a running server first (PLANE may be `all`)",
    )
    options = parser.parse_args(argv)

    for target in options.fetch:
        plane, _, url = target.partition("=")

        if not plane or not url:
            parser.error(
                "--fetch takes plane=url, e.g. --fetch environment=https://acme.cboxid.com"
            )

        configs = [p for p in PLANES if plane in ("all", p.plane)]

        if not configs:
            parser.error(f"unknown plane {plane}; use {', '.join(p.plane for p in PLANES)} or all")

        for config in configs:
            fetch_spec(config, url)

    stale = False

    for path, result in generate_all().items():
        current = path.read_text("utf-8") if path.exists() else ""

        if options.check:
            if current != result.code:
                print(f"stale: {path.relative_to(ROOT)}", file=sys.stderr)
                stale = True
            continue

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(result.code, "utf-8")
        skipped = f", skipped {len(result.skipped)} (other credentials)" if result.skipped else ""
        print(f"{path.relative_to(ROOT)}: {result.operations} operations{skipped}")

    if stale:
        print("Run `python -m scripts.generate_management` and commit the result.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
