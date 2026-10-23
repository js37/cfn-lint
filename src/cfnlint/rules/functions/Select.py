"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from cfnlint.helpers import REGEX_DYN_REF
from cfnlint.jsonschema import ValidationResult, Validator
from cfnlint.rules.functions._BaseFn import (
    BaseFn,
    all_types,
    validate_dynamic_reference_location,
)


class Select(BaseFn):
    """Check if Select values are correct"""

    id = "E1017"
    shortdesc = "Select validation of parameters"
    description = "Making sure the Select function is properly configured"
    source_url = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-select.html"
    tags = ["functions", "select"]

    def __init__(self) -> None:
        super().__init__(
            "Fn::Select",
            all_types,
            resolved_rule="W1035",
        )
        self.child_rules.update(
            {
                "E1027": None,
                "E1051": None,
            }
        )

    def schema(self, validator: Validator, instance: Any) -> dict[str, Any]:
        # When the list is hardcoded its length is fixed at authoring time
        # (a function used as a list *item* still counts as one element), so
        # the index has a known upper bound. Inject it as a ``maximum`` next
        # to the existing ``minimum`` and let the standard keyword validators
        # report an out-of-bounds index. Without this an out-of-bounds
        # ``Fn::Select`` passes linting and fails at deploy with
        # "Fn::Select cannot select nonexistent value at index N".
        _, value = self.key_value(instance)
        if not validator.is_type(value, "array") or len(value) != 2:
            return self._schema
        if not validator.is_type(value[1], "array"):
            return self._schema

        schema = deepcopy(self._schema)
        maximum = len(value[1]) - 1
        for branch in ("then", "else"):
            index_schema = schema["cfnContext"]["schema"][branch]["prefixItems"][0]
            index_schema["cfnContext"]["schema"]["maximum"] = maximum
        return schema

    def fn_select(
        self, validator: Validator, s: Any, instance: Any, schema: Any
    ) -> ValidationResult:
        yield from self.validate(validator, s, instance, schema)

        # Dispatch dynamic-reference location rules on literal string items
        # of ``Fn::Select``'s list argument. ``_filter.filter`` suppresses
        # the ``dynamicReference`` keyword inside intrinsic functions, so
        # wrapping a reference in ``Fn::Select`` would otherwise silence
        # E1027 / E1051.
        _, value = self.key_value(instance)
        if not isinstance(value, list) or len(value) != 2:
            return
        items = value[1]
        if not isinstance(items, list):
            return
        location_validator = validator.evolve(
            context=validator.context.evolve(
                path=validator.context.path.descend(path="Fn::Select")
            )
        )
        for item in items:
            if isinstance(item, str) and REGEX_DYN_REF.findall(item):
                for err in validate_dynamic_reference_location(
                    location_validator, self.child_rules, item, schema
                ):
                    err.path.append("Fn::Select")
                    yield err
