"""Pure Python Standard Library JSON Schema Subset Validator.

Implements IFC-08 / DSR-009 / DSR-073 requirements:
- Supported keywords: $schema, $id, $defs, local $ref, type, properties,
  required, additionalProperties, items, minItems, maxItems, uniqueItems,
  minLength, maxLength, minimum, maximum, enum, const, oneOf, pattern.
- Annotations: title, description.
- Rejects unsupported keywords immediately (fail-closed, not ignored).
- Rejects booleans disguised as integers/numbers.
- Rejects NaN, Infinity.
- Provides exact field path on errors.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-025  版本化 JSON Schema 与标准库子集校验器：类型、条件字段、额外属性、超限、未知关键字反例失败
#   绑定实现: DSR-006, DSR-007, DSR-009, DSR-073
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from auditkit.contracts.errors import UnsupportedSchemaError, InvalidInputError


SUPPORTED_KEYWORDS: Set[str] = {
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "enum",
    "const",
    "oneOf",
    "pattern",
    "title",
    "description",
}


class SchemaValidationError:
    """Represents a schema validation failure at a specific path.

    Requirements: SWR-025(错误带字段路径) / DSR-009(定位到字段)
    """

    def __init__(self, path: str, message: str, keyword: Optional[str] = None) -> None:
        """Record the failing instance path, message and keyword.

        Requirements: SWR-025(support) / DSR-009(support)
        """
        self.path = path or "#"
        self.message = message
        self.keyword = keyword

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the failure with its path and keyword.

        Requirements: SWR-025(support) / DSR-009(support)
        """
        return {
            "path": self.path,
            "message": self.message,
            "keyword": self.keyword,
        }

    def __str__(self) -> str:
        """Render "path: message" for logs and CLI error output.

        Requirements: SWR-025(support) / DSR-009(support)
        """
        return f"{self.path}: {self.message}"


class SchemaValidator:
    """Subset JSON Schema validator.

    Requirements: SWR-025(标准库子集校验) / DSR-007(子集设计), DSR-009(实现), DSR-073(嵌套上限)
    """

    def __init__(self, schema: Dict[str, Any], root_schema: Optional[Dict[str, Any]] = None) -> None:
        """Compile the schema and fail closed on unsupported keywords.

        Requirements: SWR-025(编译期拒绝未知关键字) / DSR-007(support)
        """
        if not isinstance(schema, dict):
            raise UnsupportedSchemaError("Schema must be a JSON object")
        self.schema = schema
        self.root_schema = root_schema or schema
        self._validate_schema_syntax(self.schema, "#")

    def _validate_schema_syntax(self, sub_schema: Any, path: str) -> None:
        """Reject any keyword outside the supported subset, recursively.

        Requirements: SWR-025(未知关键字报错,support) / DSR-007(support)
        """
        if not isinstance(sub_schema, dict):
            return
        for key, val in sub_schema.items():
            if key not in SUPPORTED_KEYWORDS:
                raise UnsupportedSchemaError(
                    f"Unsupported schema keyword '{key}' at {path}",
                    details={"path": path, "keyword": key},
                )
            if key == "properties" and isinstance(val, dict):
                for prop_name, prop_schema in val.items():
                    self._validate_schema_syntax(prop_schema, f"{path}/properties/{prop_name}")
            elif key == "items":
                self._validate_schema_syntax(val, f"{path}/items")
            elif key == "oneOf" and isinstance(val, list):
                for idx, branch in enumerate(val):
                    self._validate_schema_syntax(branch, f"{path}/oneOf/{idx}")
            elif key == "$defs" and isinstance(val, dict):
                for def_name, def_schema in val.items():
                    self._validate_schema_syntax(def_schema, f"{path}/$defs/{def_name}")

    def _resolve_ref(self, ref: str) -> Dict[str, Any]:
        """Resolve local '#/...' references only; remote refs are rejected.

        Requirements: SWR-025(仅本地引用,support) / DSR-009(support)
        """
        if not ref.startswith("#/"):
            raise UnsupportedSchemaError(f"Only local references starting with '#/' are supported, got: {ref}")
        parts = ref[2:].split("/")
        curr = self.root_schema
        for part in parts:
            if not isinstance(curr, dict) or part not in curr:
                raise UnsupportedSchemaError(f"Unresolvable local reference: {ref}")
            curr = curr[part]
        if not isinstance(curr, dict):
            raise UnsupportedSchemaError(f"Reference does not resolve to an object schema: {ref}")
        return curr

    def validate(self, instance: Any) -> List[SchemaValidationError]:
        """Validate instance and return list of validation errors (empty if valid).

        Requirements: SWR-025(类型/边界/额外属性反例) / DSR-009(正反例校验), DSR-073(条件字段)
        """
        errors: List[SchemaValidationError] = []
        self._validate_node(instance, self.schema, "#", errors, depth=0)
        return errors

    def validate_or_raise(self, instance: Any) -> None:
        """Validate instance and raise InvalidInputError if invalid.

        Requirements: SWR-025(失败可定位不静默) / DSR-009(support)
        """
        errors = self.validate(instance)
        if errors:
            first = errors[0]
            raise InvalidInputError(
                f"Schema validation failed at {first.path}: {first.message}",
                details={"errors": [e.to_dict() for e in errors]},
            )

    def _validate_node(
        self,
        instance: Any,
        sub_schema: Dict[str, Any],
        path: str,
        errors: List[SchemaValidationError],
        depth: int,
    ) -> None:
        """Apply keyword checks to one node, recording errors at exact paths.

        Requirements: SWR-025(逐节点校验记录,support) / DSR-009(support)
        """
        if depth > 100:
            errors.append(SchemaValidationError(path, "Maximum schema evaluation depth exceeded", "depth"))
            return

        # Check for NaN / Infinity in float values
        if isinstance(instance, float) and (math.isnan(instance) or math.isinf(instance)):
            errors.append(SchemaValidationError(path, "NaN and Infinity values are prohibited", "type"))
            return

        # Handle $ref
        if "$ref" in sub_schema:
            resolved = self._resolve_ref(sub_schema["$ref"])
            self._validate_node(instance, resolved, path, errors, depth + 1)
            return

        # Type checking
        if "type" in sub_schema:
            expected_type = sub_schema["type"]
            if not self._check_type(instance, expected_type):
                errors.append(
                    SchemaValidationError(
                        path,
                        f"Expected type '{expected_type}', got '{self._type_name(instance)}'",
                        "type",
                    )
                )
                return  # If base type fails, stop further type-specific checks

        # Const check
        if "const" in sub_schema:
            if instance != sub_schema["const"]:
                errors.append(
                    SchemaValidationError(
                        path,
                        f"Expected constant value {sub_schema['const']!r}, got {instance!r}",
                        "const",
                    )
                )

        # Enum check
        if "enum" in sub_schema:
            if instance not in sub_schema["enum"]:
                errors.append(
                    SchemaValidationError(
                        path,
                        f"Value {instance!r} is not in enum {sub_schema['enum']}",
                        "enum",
                    )
                )

        # String constraints
        if isinstance(instance, str):
            if "minLength" in sub_schema and len(instance) < sub_schema["minLength"]:
                errors.append(
                    SchemaValidationError(
                        path,
                        f"String length {len(instance)} is less than minLength {sub_schema['minLength']}",
                        "minLength",
                    )
                )
            if "maxLength" in sub_schema and len(instance) > sub_schema["maxLength"]:
                errors.append(
                    SchemaValidationError(
                        path,
                        f"String length {len(instance)} is greater than maxLength {sub_schema['maxLength']}",
                        "maxLength",
                    )
                )
            if "pattern" in sub_schema:
                try:
                    if not re.search(sub_schema["pattern"], instance):
                        errors.append(
                            SchemaValidationError(
                                path,
                                f"String does not match pattern {sub_schema['pattern']!r}",
                                "pattern",
                            )
                        )
                except re.error as e:
                    raise UnsupportedSchemaError(f"Invalid regex pattern {sub_schema['pattern']!r}: {e}")

        # Number / Integer constraints (strictly exclude bool)
        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            if "minimum" in sub_schema and instance < sub_schema["minimum"]:
                errors.append(
                    SchemaValidationError(
                        path,
                        f"Value {instance} is less than minimum {sub_schema['minimum']}",
                        "minimum",
                    )
                )
            if "maximum" in sub_schema and instance > sub_schema["maximum"]:
                errors.append(
                    SchemaValidationError(
                        path,
                        f"Value {instance} is greater than maximum {sub_schema['maximum']}",
                        "maximum",
                    )
                )

        # Array constraints
        if isinstance(instance, list):
            if "minItems" in sub_schema and len(instance) < sub_schema["minItems"]:
                errors.append(
                    SchemaValidationError(
                        path,
                        f"Array length {len(instance)} is less than minItems {sub_schema['minItems']}",
                        "minItems",
                    )
                )
            if "maxItems" in sub_schema and len(instance) > sub_schema["maxItems"]:
                errors.append(
                    SchemaValidationError(
                        path,
                        f"Array length {len(instance)} is greater than maxItems {sub_schema['maxItems']}",
                        "maxItems",
                    )
                )
            if sub_schema.get("uniqueItems") is True:
                # Check uniqueness by serialization
                seen: Set[str] = set()
                import json
                for item in instance:
                    dumped = json.dumps(item, sort_keys=True)
                    if dumped in seen:
                        errors.append(SchemaValidationError(path, "Array items must be unique", "uniqueItems"))
                        break
                    seen.add(dumped)
            if "items" in sub_schema and isinstance(sub_schema["items"], dict):
                item_schema = sub_schema["items"]
                for idx, item in enumerate(instance):
                    self._validate_node(item, item_schema, f"{path}/{idx}", errors, depth + 1)

        # Object constraints
        if isinstance(instance, dict):
            # Required fields
            if "required" in sub_schema:
                for req in sub_schema["required"]:
                    if req not in instance:
                        errors.append(
                            SchemaValidationError(
                                path,
                                f"Missing required property '{req}'",
                                "required",
                            )
                        )
            properties = sub_schema.get("properties", {})
            additional_props = sub_schema.get("additionalProperties", True)

            for prop_name, prop_val in instance.items():
                if prop_name in properties:
                    self._validate_node(
                        prop_val,
                        properties[prop_name],
                        f"{path}/{prop_name}",
                        errors,
                        depth + 1,
                    )
                else:
                    if additional_props is False:
                        errors.append(
                            SchemaValidationError(
                                f"{path}/{prop_name}",
                                f"Additional property '{prop_name}' is not allowed",
                                "additionalProperties",
                            )
                        )
                    elif isinstance(additional_props, dict):
                        self._validate_node(
                            prop_val,
                            additional_props,
                            f"{path}/{prop_name}",
                            errors,
                            depth + 1,
                        )

        # oneOf constraint
        if "oneOf" in sub_schema and isinstance(sub_schema["oneOf"], list):
            matched = 0
            for branch in sub_schema["oneOf"]:
                branch_errors: List[SchemaValidationError] = []
                self._validate_node(instance, branch, path, branch_errors, depth + 1)
                if not branch_errors:
                    matched += 1
            if matched != 1:
                errors.append(
                    SchemaValidationError(
                        path,
                        f"Instance must match exactly one oneOf branch, matched: {matched}",
                        "oneOf",
                    )
                )

    def _check_type(self, instance: Any, expected: str) -> bool:
        """Strict type check: booleans never count as integers or numbers.

        Requirements: SWR-025(布尔非整数) / DSR-009(严格类型)
        """
        if expected == "string":
            return isinstance(instance, str)
        elif expected == "integer":
            # In Python, bool is a subclass of int! Reject booleans as integers.
            return isinstance(instance, int) and not isinstance(instance, bool)
        elif expected == "number":
            return isinstance(instance, (int, float)) and not isinstance(instance, bool)
        elif expected == "boolean":
            return isinstance(instance, bool)
        elif expected == "array":
            return isinstance(instance, list)
        elif expected == "object":
            return isinstance(instance, dict)
        elif expected == "null":
            return instance is None
        return False

    def _type_name(self, instance: Any) -> str:
        """Return the JSON type name used in error messages (bool before int).

        Requirements: SWR-025(support) / DSR-009(support)
        """
        if instance is None:
            return "null"
        if isinstance(instance, bool):
            return "boolean"
        if isinstance(instance, int):
            return "integer"
        if isinstance(instance, float):
            return "number"
        if isinstance(instance, str):
            return "string"
        if isinstance(instance, list):
            return "array"
        if isinstance(instance, dict):
            return "object"
        return type(instance).__name__
