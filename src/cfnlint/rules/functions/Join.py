"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

from typing import Any

from cfnlint.helpers import REGEX_DYN_REF
from cfnlint.jsonschema import ValidationResult
from cfnlint.jsonschema.protocols import Validator
from cfnlint.rules.functions._BaseFn import BaseFn, validate_dynamic_reference_location


class Join(BaseFn):
    """Check if Join values are correct"""

    id = "E1022"
    shortdesc = "Join validation of parameters"
    description = "Making sure the join function is properly configured"
    source_url = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-join.html"
    tags = ["functions", "join"]

    def __init__(self) -> None:
        super().__init__(
            "Fn::Join",
            ("string",),
            resolved_rule="W1032",
        )
        self.child_rules.update(
            {
                "I1022": None,
                "E1027": None,
                "E1051": None,
            }
        )

    def fn_join(
        self, validator: Validator, s: Any, instance: Any, schema: Any
    ) -> ValidationResult:
        validator = validator.evolve(
            context=validator.context.evolve(strict_types=True)
        )
        errs = list(super().validate(validator, s, instance, schema))
        if errs:
            yield from iter(errs)

        for rule_id, rule in self.child_rules.items():
            if rule_id in {"E1027", "E1051"}:
                continue
            if rule is None or not hasattr(rule, "validate"):
                continue

            yield from rule.validate(validator, s, instance, schema)

        # Dispatch dynamic-reference location rules on each literal string
        # item of ``Fn::Join``'s value list. ``_filter.filter`` suppresses
        # the ``dynamicReference`` keyword inside intrinsic functions, so
        # wrapping a reference such as ``{{resolve:ssm-secure:...}}`` in
        # ``Fn::Join`` would otherwise silence E1027 / E1051.
        _, value = self.key_value(instance)
        if isinstance(value, list) and len(value) == 2:
            items = value[1]
            if isinstance(items, list):
                location_validator = validator.evolve(
                    context=validator.context.evolve(
                        path=validator.context.path.descend(path="Fn::Join")
                    )
                )
                for item in items:
                    if isinstance(item, str) and REGEX_DYN_REF.findall(item):
                        for err in validate_dynamic_reference_location(
                            location_validator,
                            self.child_rules,
                            item,
                            schema,
                        ):
                            err.path.append("Fn::Join")
                            yield err
