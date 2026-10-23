"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

from typing import Any

from cfnlint.helpers import FUNCTIONS_SINGLE, REGEX_DYN_REF
from cfnlint.jsonschema import ValidationResult, Validator
from cfnlint.rules.functions._BaseFn import BaseFn, validate_dynamic_reference_location


class Base64(BaseFn):
    """Check if Base64 values are correct"""

    id = "E1021"
    shortdesc = "Base64 validation of parameters"
    description = "Making sure the Base64 function is properly configured"
    source_url = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-base64.html"
    tags = ["functions", "base64"]

    def __init__(self) -> None:
        super().__init__(
            "Fn::Base64",
            ("string",),
            tuple(FUNCTIONS_SINGLE),
        )
        self.child_rules.update(
            {
                "E1027": None,
                "E1051": None,
            }
        )

    def fn_base64(
        self, validator: Validator, s: Any, instance: Any, schema: Any
    ) -> ValidationResult:
        yield from self.validate(validator, s, instance, schema)

        # Dispatch dynamic-reference location rules on the literal string
        # argument of ``Fn::Base64``. ``_filter.filter`` suppresses the
        # ``dynamicReference`` keyword inside intrinsic functions, so
        # wrapping a reference in ``Fn::Base64`` would otherwise silence
        # E1027 / E1051.
        _, value = self.key_value(instance)
        if isinstance(value, str) and REGEX_DYN_REF.findall(value):
            location_validator = validator.evolve(
                context=validator.context.evolve(
                    path=validator.context.path.descend(path="Fn::Base64")
                )
            )
            for err in validate_dynamic_reference_location(
                location_validator, self.child_rules, value, schema
            ):
                err.path.append("Fn::Base64")
                yield err
