"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import regex as re

from cfnlint._typing import RuleMatches
from cfnlint.helpers import FUNCTIONS, REGEX_DYN_REF, REGEX_DYN_REF_SSM
from cfnlint.rules import CloudFormationLintRule, RuleMatch
from cfnlint.template import Template


class Password(CloudFormationLintRule):
    """Check if Password Properties are properly configured"""

    id = "W2501"
    shortdesc = "Check if Password Properties are correctly configured"
    description = (
        "Password properties should not be strings and if parameter using NoEcho"
    )
    source_url = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html#creds"
    tags = ["parameters", "passwords", "security", "dynamic reference"]

    def _report_string(self, value, tree, matches):
        """Apply the hardcoded / dynamic-reference checks to a literal string
        contributed to a password property value."""
        if re.match(REGEX_DYN_REF, value):
            if re.match(REGEX_DYN_REF_SSM, value):
                message = (
                    "Password should use a secure dynamic reference for"
                    f" {'/'.join(map(str, tree[:-1]))}"
                )
                matches.append(RuleMatch(tree[:-1], message))
        else:
            message = (
                "Password shouldn't be hardcoded for"
                f" {'/'.join(map(str, tree[:-1]))}"
            )
            matches.append(RuleMatch(tree[:-1], message))

    def _check_value(
        self,
        obj,
        tree,
        cfn,
        parameters,
        password_property,
        matches,
        fix_params,
    ):
        """Dispatch on the resolved shape of a password property value and
        recurse into intrinsic functions so literal fragments contributed by
        Fn::Join / Fn::Sub / Fn::Base64 / Fn::If are inspected."""
        if isinstance(obj, str):
            self._report_string(obj, tree, matches)
            return
        # bool is a subclass of int - handle both as hardcoded scalar literals.
        if isinstance(obj, (int, float, bool)):
            message = (
                "Password shouldn't be hardcoded for"
                f" {'/'.join(map(str, tree[:-1]))}"
            )
            matches.append(RuleMatch(tree[:-1], message))
            return
        if not isinstance(obj, dict):
            return
        if len(obj) == 1:
            key, value = next(iter(obj.items()))
            if key == "Ref":
                if value in parameters:
                    param = cfn.template["Parameters"][value]
                    if "NoEcho" in param:
                        if not param["NoEcho"]:
                            fix_params.append(
                                {
                                    "Name": value,
                                    "Use": password_property,
                                }
                            )
                    else:
                        fix_params.append(
                            {"Name": value, "Use": password_property}
                        )
                return
            if key in FUNCTIONS:
                self._check_function(
                    key,
                    value,
                    tree,
                    cfn,
                    parameters,
                    password_property,
                    matches,
                    fix_params,
                )
                return
            # Single-key map that is neither Ref nor a recognised intrinsic
            # function - preserve the original "inappropriate map" intent.
            message = (
                "Inappropriate map found for password on"
                f" {'/'.join(map(str, tree[:-1]))}"
            )
            matches.append(RuleMatch(tree[:-1], message))
            return
        # Multi-key map - cannot be a valid intrinsic function form.
        message = (
            "Inappropriate map found for password on"
            f" {'/'.join(map(str, tree[:-1]))}"
        )
        matches.append(RuleMatch(tree[:-1], message))

    def _check_function(
        self,
        key,
        value,
        tree,
        cfn,
        parameters,
        password_property,
        matches,
        fix_params,
    ):
        """Inspect the literal string fragments contributed by an intrinsic
        function form that resolves to the password property value.

        This is a best-effort traversal: forms whose output we cannot assume
        is attacker-visible plaintext (ImportValue, GetAtt, FindInMap, ...)
        are left alone, matching cfn-lint's documented best-effort stance on
        value resolution.
        """
        if key == "Fn::Sub":
            # Fn::Sub: str  OR  Fn::Sub: [str, {var: ...}]
            literal = None
            if isinstance(value, str):
                literal = value
            elif isinstance(value, list) and value and isinstance(value[0], str):
                literal = value[0]
            if literal is not None:
                self._report_string(literal, tree, matches)
            return
        if key == "Fn::Join":
            # Fn::Join: [delimiter, [part, part, ...]]
            if (
                isinstance(value, list)
                and len(value) == 2
                and isinstance(value[1], list)
            ):
                delimiter = value[0] if isinstance(value[0], str) else ""
                literal_parts = [
                    part for part in value[1] if isinstance(part, str)
                ]
                if literal_parts:
                    joined = delimiter.join(literal_parts)
                    self._report_string(joined, tree, matches)
                # Also recurse into any nested intrinsic parts so an inner
                # Ref/Fn::If still contributes its own findings.
                for part in value[1]:
                    if isinstance(part, dict):
                        self._check_value(
                            part,
                            tree,
                            cfn,
                            parameters,
                            password_property,
                            matches,
                            fix_params,
                        )
            return
        if key == "Fn::Base64":
            self._check_value(
                value,
                tree,
                cfn,
                parameters,
                password_property,
                matches,
                fix_params,
            )
            return
        if key == "Fn::If":
            # Fn::If: [condition, true_value, false_value]
            if isinstance(value, list) and len(value) == 3:
                for branch in value[1:]:
                    self._check_value(
                        branch,
                        tree,
                        cfn,
                        parameters,
                        password_property,
                        matches,
                        fix_params,
                    )
            return
        # Other recognised functions (GetAtt, ImportValue, FindInMap,
        # Select, Split, GetAZs, Cidr, Transform, ...) are opaque: we have
        # no visible literal to flag, so remain silent.

    def match(self, cfn: Template) -> RuleMatches:
        """Check CloudFormation Password Parameters"""

        matches = []
        password_properties = [
            "AccountPassword",
            "AdminPassword",
            "ADDomainJoinPassword",
            "CrossRealmTrustPrincipalPassword",
            "KdcAdminPassword",
            "Password",
            "DbPassword",
            "MasterUserPassword",
            "PasswordParam",
        ]

        parameters = list(cfn.template.get("Parameters", {}).keys())
        fix_params = []
        for password_property in password_properties:
            # Build the list of refs
            refs = cfn.search_deep_keys(password_property)
            trees = []
            for tree in refs:
                if len(tree) > 2:
                    if tree[0] == "Resources" and tree[2] == "Properties":
                        trees.append(tree)

            for tree in trees:
                obj = tree[-1]
                self._check_value(
                    obj,
                    tree,
                    cfn,
                    parameters,
                    password_property,
                    matches,
                    fix_params,
                )

        # Deduplicate collected parameter fixes so recursion through
        # intrinsic functions does not produce multiple warnings for the
        # same (parameter, usage) pair.
        seen = set()
        unique_fix_params = []
        for paramname in fix_params:
            key = (paramname["Name"], paramname["Use"])
            if key in seen:
                continue
            seen.add(key)
            unique_fix_params.append(paramname)
        fix_params = unique_fix_params

        for paramname in fix_params:
            message = (
                f"Parameter {paramname['Name']} used as {paramname['Use']}, therefore"
                " NoEcho should be True"
            )
            tree = ["Parameters", paramname["Name"]]
            matches.append(RuleMatch(tree, message))
        return matches
