"""Strict schema validation and repair feedback that omits supplied values."""

from collections.abc import Callable
import json
from typing import TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class InvalidOutput(ValueError):
    def __init__(self, errors: tuple[str, ...]) -> None:
        super().__init__("Invalid model output")
        self.errors = errors


def check_model(model: type[BaseModel]) -> None:
    config = model.model_config
    if config.get("frozen") is not True or config.get("extra") != "forbid":
        raise ValueError("Model output schema must be frozen and forbid extra fields")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields: dict[str, object] = {}
    for name, value in pairs:
        if name in fields:
            raise InvalidOutput(("duplicate_field",))
        fields[name] = value
    return fields


def _invalid_constant(_: str) -> None:
    raise InvalidOutput(("nonfinite_number",))


def parse_output(
    text: str, model: type[T], validate: Callable[[T], None] | None = None,
) -> T:
    try:
        json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except InvalidOutput:
        raise
    except (ValueError, RecursionError) as exc:
        raise InvalidOutput(("invalid_json",)) from exc

    try:
        output = model.model_validate_json(text, strict=True)
    except ValidationError as exc:
        errors = []
        for issue in exc.errors(include_url=False, include_context=False, include_input=False)[:8]:
            # Only declared field names are safe to echo. Unknown keys and
            # validation messages can contain arbitrary model output.
            field = issue["loc"][0] if issue["loc"] else None
            prefix = f"{field}: " if isinstance(field, str) and field in model.model_fields else ""
            errors.append(prefix + issue["type"])
        raise InvalidOutput(tuple(errors)) from exc

    if validate is not None:
        try:
            validate(output)
        except ValueError as exc:
            raise InvalidOutput(("output references must match the supplied evidence",)) from exc
    return output
