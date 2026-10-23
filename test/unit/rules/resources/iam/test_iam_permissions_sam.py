"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from collections import deque

import pytest

from cfnlint.rules.resources.iam.Permissions import Permissions


@pytest.fixture(scope="module")
def rule():
    rule = Permissions()
    yield rule


@pytest.fixture
def template():
    return {
        "Transform": "AWS::Serverless-2016-10-31",
    }


@pytest.mark.parametrize(
    "name,instance,path,err_count",
    [
        # The SAM escape only applies to policies attached to a SAM-native
        # ``AWS::Serverless::*`` resource (whose IAM content is synthesised
        # from policy templates cfn-lint may not know about).
        (
            "SAM function policy is skipped",
            "",
            {
                "cfn_path": deque(
                    ["Resources", "AWS::Serverless::Function", "Properties"]
                )
            },
            0,
        ),
        # A hand-written raw-CFN IAM policy must still be validated even
        # when the template declares the SAM transform: a
        # template-controlled ``Transform`` declaration must not silently
        # disable IAM action validation.
        (
            "Raw-CFN IAM policy is still validated under SAM transform",
            "",
            {
                "cfn_path": deque(
                    ["Resources", "AWS::IAM::ManagedPolicy", "Properties"]
                )
            },
            1,
        ),
    ],
    indirect=["path"],
)
def test_permissions(name, instance, err_count, rule, validator):
    errors = list(rule.validate(validator, {}, instance, {}))
    assert len(errors) == err_count, f"Test {name!r} got {errors!r}"
