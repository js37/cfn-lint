"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Any

import regex as re

from cfnlint.data import AdditionalSpecs
from cfnlint.helpers import REGEX_DYN_REF, ensure_list, is_function, load_resource
from cfnlint.jsonschema import ValidationError, ValidationResult, Validator
from cfnlint.rules.helpers import get_value_from_path
from cfnlint.rules.jsonschema.CfnLintKeyword import CfnLintKeyword

LOGGER = logging.getLogger(__name__)


class _Arn:
    def __init__(self, full_arn: str):
        arn_parts = full_arn.split(":", 5)

        self._parts: list[str] = ["*", "*", "*", "*", "*", "*"]

        for i, arn_part in enumerate(arn_parts):
            self._parts[i] = arn_part

    def __repr__(self):
        return ":".join(self._parts)

    @property
    def parts(self):
        return self._parts

    def __eq__(self, value: Any):
        if not isinstance(value, _Arn):
            return False

        for i in range(0, 5):
            if self.parts[i] == "*":
                continue
            if value.parts[i] in ["${Partition}", "${Region}", "${Account}"]:
                continue
            if self.parts[i] != value.parts[i]:
                return False

        if self.parts[5] == "*":
            return True

        delimiter = None
        if ":" in value.parts[5]:
            delimiter = ":"
        elif "/" in value.parts[5]:
            delimiter = "/"

        if not delimiter:
            return True

        for x, y in zip(
            self.parts[5].split(delimiter), value.parts[5].split(delimiter)
        ):
            if x == y:
                continue
            if x == "*" or x.startswith("*") or y == "" or y == ".*":
                return True
            if x.startswith(y) and "*" in x:
                return True

            return False

        return True


class StatementResources(CfnLintKeyword):
    id = "I3510"
    shortdesc = "Validate statement resources match the actions"
    description = (
        "IAM policy statements have different constraints between actions and "
        "resources. This rule validates that resource ARNs or asterisks match "
        "the actions."
    )
    source_url = "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/iam-access-control-overview-cwl.html"
    tags = ["resources", "iam"]

    def __init__(self):
        super().__init__(
            ["AWS::IAM::Policy/Properties/PolicyDocument/Statement"],
        )
        self.service_map = load_resource(AdditionalSpecs, "Policies.json")

    def validate(
        self, validator: Validator, keywords: Any, instance: Any, schema: dict[str, Any]
    ) -> ValidationResult:
        if not validator.is_type(instance, "object"):
            return

        # Collect one scenario per `get_value_from_path` yield (i.e. one per
        # Fn::If branch, per Resource/NotResource key). Each scenario tracks
        # its own literal ARNs and whether it contained a wildcard or an
        # unresolvable (dynamic reference / parameter Ref / other intrinsic)
        # entry.  Keeping these flags local to the scenario prevents a single
        # unresolvable or `*` entry from suppressing action/resource checks
        # for sibling entries, sibling branches, or other actions in the
        # statement.
        scenarios: list[dict[str, Any]] = []
        saw_any_resource_key = False
        for key in ["Resource", "NotResource"]:
            for resources, _ in get_value_from_path(
                validator, instance, path=deque([key])
            ):
                saw_any_resource_key = True
                resources = ensure_list(resources)

                scenario_literals: set[str] = set()
                scenario_wildcard = False
                scenario_unresolvable = False
                for resource in resources:
                    if isinstance(resource, str):
                        if re.match(REGEX_DYN_REF, resource):
                            # value is a {{resolve:...}} dynamic reference;
                            # unknown at lint time -- skip this single entry.
                            scenario_unresolvable = True
                            continue
                        if resource == "*":
                            # universal wildcard -- any action matches in this
                            # scenario.
                            scenario_wildcard = True
                            continue
                        scenario_literals.add(resource)
                    else:
                        k, v = is_function(resource)
                        if k is None:
                            continue
                        if (
                            k == "Ref"
                            and validator.is_type(v, "string")
                            and v in validator.context.parameters
                        ):
                            # Ref to a template parameter -- value supplied at
                            # deploy time; skip this single entry.
                            scenario_unresolvable = True
                            continue
                        # Any other intrinsic (Fn::Sub, Fn::GetAtt, Fn::Join,
                        # Fn::ImportValue, ...) is unresolvable for this entry
                        # only.
                        scenario_unresolvable = True
                        continue

                scenarios.append(
                    {
                        "literals": [_Arn(a) for a in scenario_literals],
                        "wildcard": scenario_wildcard,
                        "unresolvable": scenario_unresolvable,
                    }
                )

        if not saw_any_resource_key:
            return

        # If no scenario yielded any usable information (no literals, no
        # wildcard) emit a debug message so an opted-in pipeline can see that
        # the check could not be evaluated, rather than silently returning.
        if scenarios and all(
            not s["literals"] and not s["wildcard"] for s in scenarios
        ):
            LOGGER.debug(
                "StatementResources (I3510): skipping action/resource match; "
                "statement contains only unresolvable Resource/NotResource "
                "entries (dynamic references, parameter Refs, or intrinsics)."
            )
            return

        for actions, _ in get_value_from_path(
            validator, instance, path=deque(["Action"])
        ):
            actions = ensure_list(actions)

            for action in actions:
                if not validator.is_type(action, "string"):
                    continue
                if any(x in action for x in ["*", "?"]):
                    continue
                if ":" not in action:
                    continue
                service, permission = action.split(":", 1)
                service = service.lower()
                permission = permission.lower()

                if service not in self.service_map:
                    continue

                if permission not in self.service_map[service]["Actions"]:
                    continue

                resources = self.service_map[service]["Actions"][permission].get(
                    "Resources", None
                )
                if isinstance(resources, (list, str)):
                    resources = ensure_list(resources)
                    arn_formats = None
                    # The action is satisfied if, in every scenario, at least
                    # one literal resource matches an allowed ARN format, the
                    # scenario has a universal wildcard, or the scenario is
                    # entirely unresolvable (no literals and no wildcard --
                    # that case is filtered above, but defensive here).
                    action_ok = True
                    for scenario in scenarios:
                        if scenario["wildcard"]:
                            continue
                        if (
                            not scenario["literals"]
                            and scenario["unresolvable"]
                        ):
                            # Entirely unresolvable scenario -- cannot assert
                            # a mismatch without a false positive.
                            continue
                        matched = False
                        for resource in resources:
                            # use lower as certain resources are described in
                            # actions with upper case letters and in resources
                            # as lower case issue #4036
                            arn_formats = self.service_map[service][
                                "Resources"
                            ][resource.lower()].get("ARNFormats")
                            for arn_format in arn_formats:
                                arn = _Arn(arn_format)
                            if arn in scenario["literals"]:
                                matched = True
                                break
                        if matched:
                            continue
                        action_ok = False
                        break
                    if not action_ok:
                        yield ValidationError(
                            f"action {action!r} requires a resource of {arn_formats!r}",
                            path=deque(["Resource"]),
                            rule=self,
                        )
                else:
                    LOGGER.debug(f"action {action!r} requires a resource of '*'")
                    # yield ValidationError(
                    #    f"action {action!r} requires a resource of '*'",
                    #    path=deque(["Resource"]),
                    #    rule=self,
                    # )
