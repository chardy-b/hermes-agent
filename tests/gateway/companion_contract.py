"""Pinned WIL-46 OpenAPI validation for real companion HTTP tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import yaml
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

CONTRACT_PATH = Path(__file__).parent / "contracts" / "companion-v1.openapi.yaml"
CONTRACT_SHA256 = "040a4c215c09c15010e8e554203ba5f2b2b5e86761fb9a3e3aec197a1fa88c38"
_BASE_PATH = "/companion/v1"
_HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}
_MISSING = object()

# WIL-47 intentionally exposes operator-wide chat-session listing rather than
# the device-owned GET /sessions authorization inherited by WIL-46. Its
# session-revoke operation is not present in WIL-46 at all. Keep those deltas
# explicit instead of misrepresenting them as upstream contract definitions.
_WIL47_SECURITY_OVERRIDES = {
    "listSessions": [{"operatorBearerAuth": []}],
}
_WIL47_OPERATIONS = {
    "revokeSession": {
        "method": "post",
        "path": "/sessions/{sessionId}/revoke",
        "operation": {
            "operationId": "revokeSession",
            "security": [{"operatorBearerAuth": []}],
            "parameters": [
                {"$ref": "#/components/parameters/SessionId"},
                {"$ref": "#/components/parameters/IdempotencyKey"},
            ],
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/RevokeDeviceRequest"}
                    }
                },
            },
            "responses": {
                "200": {
                    "description": "Session revocation applied or already applied",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": [
                                    "sessionId",
                                    "deviceId",
                                    "status",
                                    "revokedAt",
                                ],
                                "additionalProperties": False,
                                "properties": {
                                    "sessionId": {
                                        "$ref": "#/components/schemas/PublicId"
                                    },
                                    "deviceId": {
                                        "$ref": "#/components/schemas/PublicId"
                                    },
                                    "status": {"type": "string", "const": "revoked"},
                                    "revokedAt": {
                                        "$ref": "#/components/schemas/Timestamp"
                                    },
                                },
                            }
                        }
                    },
                },
                "401": {"$ref": "#/components/responses/Unauthorized"},
                "403": {"$ref": "#/components/responses/Forbidden"},
                "404": {"$ref": "#/components/responses/NotFound"},
            },
        },
    }
}


@dataclass(frozen=True)
class Operation:
    method: str
    path: str
    spec: dict[str, Any]
    path_item: dict[str, Any]


class CompanionContract:
    """Validate HTTP exchanges against the pinned OpenAPI operations.

    JSON Schema reference handling is delegated to jsonschema/referencing. The
    small amount of code here only selects the named OpenAPI operation, media
    type, parameters, and response status used by the real aiohttp request.
    """

    def __init__(self) -> None:
        raw = CONTRACT_PATH.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        assert digest == CONTRACT_SHA256, (
            "Pinned WIL-46 contract drifted: refresh it from the provenance "
            f"record and update the reviewed digest (got {digest})"
        )
        self.document = yaml.safe_load(raw)
        resource = Resource.from_contents(
            self.document,
            default_specification=DRAFT202012,
        )
        self.registry = Registry().with_resource("urn:companion-v1", resource)
        self.resolver = self.registry.resolver("urn:companion-v1")

    def operation(self, operation_id: str) -> Operation:
        extension = _WIL47_OPERATIONS.get(operation_id)
        if extension is not None:
            return Operation(
                extension["method"],
                extension["path"],
                extension["operation"],
                {},
            )

        matches = []
        for path, path_item in self.document["paths"].items():
            for method, spec in path_item.items():
                if (
                    method.lower() in _HTTP_METHODS
                    and isinstance(spec, dict)
                    and spec.get("operationId") == operation_id
                ):
                    matches.append(Operation(method.lower(), path, spec, path_item))
        assert len(matches) == 1, (
            f"Expected exactly one OpenAPI operation {operation_id}"
        )
        return matches[0]

    def _resolve(self, value: dict[str, Any]) -> dict[str, Any]:
        while "$ref" in value:
            value = self.resolver.lookup(value["$ref"]).contents
        return value

    def _validate_schema(self, schema: dict[str, Any], value: Any) -> None:
        def qualify_local_refs(node: Any) -> Any:
            if isinstance(node, dict):
                return {
                    key: (
                        f"urn:companion-v1{item}"
                        if key == "$ref"
                        and isinstance(item, str)
                        and item.startswith("#/")
                        else qualify_local_refs(item)
                    )
                    for key, item in node.items()
                }
            if isinstance(node, list):
                return [qualify_local_refs(item) for item in node]
            return node

        jsonschema.Draft202012Validator(
            qualify_local_refs(schema),
            registry=self.registry,
            format_checker=jsonschema.FormatChecker(),
        ).validate(value)

    def validate_schema(self, schema_name: str, value: Any) -> None:
        """Validate an implementation-only response against a WIL-46 schema."""
        self._validate_schema(
            {"$ref": f"urn:companion-v1#/components/schemas/{schema_name}"},
            value,
        )

    def _parameters(self, operation: Operation) -> list[dict[str, Any]]:
        return [
            self._resolve(parameter)
            for parameter in (
                list(operation.path_item.get("parameters", []))
                + list(operation.spec.get("parameters", []))
            )
        ]

    @staticmethod
    def _coerce_parameter(value: str, schema: dict[str, Any]) -> Any:
        if schema.get("type") == "integer":
            try:
                return int(value)
            except ValueError:
                return value
        return value

    def validate_request(
        self,
        operation: Operation,
        *,
        headers: Any,
        query: Any,
        body: Any = _MISSING,
        path_parameters: dict[str, str] | None = None,
    ) -> None:
        path_parameters = path_parameters or {}
        request_body = operation.spec.get("requestBody")
        if request_body is not None:
            request_body = self._resolve(request_body)
            assert body is not _MISSING or not request_body.get("required", False)
            if body is not _MISSING:
                assert headers.get("Content-Type", "").split(";", 1)[0] == (
                    "application/json"
                )
                schema = request_body["content"]["application/json"]["schema"]
                self._validate_schema(schema, body)
        else:
            assert body is _MISSING

        parameters = self._parameters(operation)
        declared_query_names = {
            parameter["name"] for parameter in parameters if parameter["in"] == "query"
        }
        assert set(query) <= declared_query_names
        for parameter in parameters:
            location = parameter["in"]
            name = parameter["name"]
            source = {
                "header": headers,
                "query": query,
                "path": path_parameters,
            }[location]
            value = source.get(name)
            if parameter.get("required"):
                assert value is not None, (
                    f"Missing required {location} parameter {name}"
                )
            if value is not None:
                self._validate_schema(
                    parameter.get("schema", {}),
                    self._coerce_parameter(value, parameter.get("schema", {})),
                )

        security = _WIL47_SECURITY_OVERRIDES.get(
            operation.spec["operationId"],
            operation.spec.get("security", self.document.get("security", [])),
        )
        if security:
            alternatives_satisfied = []
            for requirement in security:
                satisfied = True
                for scheme_name in requirement:
                    scheme = self.document["components"]["securitySchemes"][scheme_name]
                    if scheme["type"] == "http":
                        satisfied &= headers.get("Authorization", "").startswith(
                            "Bearer "
                        )
                    elif scheme["type"] == "apiKey" and scheme["in"] == "header":
                        satisfied &= bool(headers.get(scheme["name"]))
                    else:  # pragma: no cover - contract guard for unsupported additions
                        raise AssertionError(
                            f"Unsupported security scheme: {scheme_name}"
                        )
                alternatives_satisfied.append(satisfied)
            assert any(alternatives_satisfied), (
                "Request does not satisfy operation security"
            )

    def validate_response(
        self,
        operation: Operation,
        *,
        status: int,
        content_type: str,
        body: Any,
    ) -> None:
        response = operation.spec["responses"].get(str(status))
        assert response is not None, (
            f"HTTP {status} is not declared for {operation.spec['operationId']}"
        )
        response = self._resolve(response)
        content = response.get("content", {})
        assert content_type in content, (
            f"Content-Type {content_type} is not declared for "
            f"{operation.spec['operationId']} HTTP {status}"
        )
        self._validate_schema(content[content_type]["schema"], body)

    async def assert_exchange(
        self,
        response: Any,
        operation_id: str,
        *,
        request_body: Any = _MISSING,
        path_parameters: dict[str, str] | None = None,
        validate_request: bool = True,
    ) -> Any:
        operation = self.operation(operation_id)
        path_parameters = path_parameters or {}
        rendered_path = operation.path
        for name, value in path_parameters.items():
            rendered_path = rendered_path.replace(f"{{{name}}}", value)
        assert "{" not in rendered_path
        assert response.request_info.method.lower() == operation.method
        assert response.url.path == _BASE_PATH + rendered_path

        if validate_request:
            self.validate_request(
                operation,
                headers=response.request_info.headers,
                query=response.url.query,
                body=request_body,
                path_parameters=path_parameters,
            )

        content_type = response.headers.get("Content-Type", "").split(";", 1)[0]
        body = await response.json()
        self.validate_response(
            operation,
            status=response.status,
            content_type=content_type,
            body=body,
        )
        return body
