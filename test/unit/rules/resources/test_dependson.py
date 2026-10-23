"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from collections import deque

import pytest

from cfnlint.context import Path
from cfnlint.context.context import Resource
from cfnlint.jsonschema import ValidationError
from cfnlint.rules.resources.DependsOn import DependsOn  # noqa: E501


@pytest.fixture(scope="module")
def rule():
    rule = DependsOn()
    yield rule


@pytest.fixture
def template():
    return {
        "Conditions": {
            "IsUsEast1": {
                "Fn::Equals": [
                    {"Ref": "AWS::Region"},
                    "us-east-1",
                ]
            }
        },
        "Resources": {
            "ParentBucket": {
                "Type": "AWS::S3::Bucket",
            },
            "ChildBucket": {
                "Type": "AWS::S3::Bucket",
                "DependsOn": "ParentBucket",
            },
            "ParentBucketWithGoodCondition": {
                "Condition": "IsUsEast1",
                "Type": "AWS::S3::Bucket",
            },
            "ChildBucketWithGoodCondition": {
                "Condition": "IsUsEast1",
                "DependsOn": "ParentBucketWithGoodCondition",
            },
            "ParentBucketWithBadCondition": {
                "Condition": "IsUsEast1",
                "Type": "AWS::S3::Bucket",
            },
            "ChildBucketWithBadCondition": {
                "Type": "AWS::S3::Bucket",
                "DependsOn": "ParentBucketWithBadCondition",
            },
            "ToMySelf": {
                "Type": "AWS::S3::Bucket",
                "DependsOn": "ToMySelf",
            },
        },
    }


@pytest.mark.parametrize(
    "name,instance,path,expected",
    [
        (
            "Valid depends on",
            "ParentBucket",
            deque(["Resources", "ChildBucket", "DependsOn"]),
            [],
        ),
        (
            "Invalid depends on but low path",
            "Foo",
            deque([]),
            [
                ValidationError(
                    "'Foo' is not one of ['ParentBucket', "
                    "'ChildBucket', "
                    "'ParentBucketWithGoodCondition', "
                    "'ParentBucketWithBadCondition', "
                    "'ChildBucketWithBadCondition', 'ToMySelf']",
                )
            ],
        ),
        (
            "Valid depends on with conditions",
            "ParentBucketWithGoodCondition",
            deque(["Resources", "ChildBucketWithGoodCondition", "DependsOn"]),
            [],
        ),
        (
            "Invalid type isn't validated by this rule",
            {"Ref": "MyResource"},
            deque(["Resources", "ChildBucket", "DependsOn"]),
            [],
        ),
        (
            "Invalid depends on",
            "Foo",
            deque(["Resources", "ChildBucket", "DependsOn"]),
            [
                ValidationError(
                    "'Foo' is not one of ['ParentBucket', "
                    "'ParentBucketWithGoodCondition', "
                    "'ParentBucketWithBadCondition', "
                    "'ChildBucketWithBadCondition', 'ToMySelf']",
                )
            ],
        ),
        (
            "Invalid depends on with conditions",
            "ParentBucketWithBadCondition",
            deque(["Resources", "ChildBucketWithBadCondition", "DependsOn"]),
            [
                ValidationError(
                    "'ParentBucketWithBadCondition' will not exist when condition "
                    "'IsUsEast1' is False",
                )
            ],
        ),
        (
            "Invalid depends on relying on itself",
            "ToMySelf",
            deque(["Resources", "ToMySelf", "DependsOn"]),
            [
                ValidationError(
                    "'ToMySelf' is not one of ['ParentBucket', 'ChildBucket', "
                    "'ParentBucketWithGoodCondition', "
                    "'ParentBucketWithBadCondition', 'ChildBucketWithBadCondition']",
                )
            ],
        ),
    ],
)
def test_validate(name, instance, path, expected, rule, validator):
    validator = validator.evolve(context=validator.context.evolve(path=Path(path)))
    errs = list(rule.validate(validator, False, instance, {}))

    assert errs == expected, f"Test {name!r} got {errs!r}"


def test_validate_with_no_cfn(rule, validator):
    validator = validator.evolve(
        context=validator.context.evolve(
            path=Path(path=deque(["Resources", "ChildBucket", "DependsOn"]))
        )
    )
    validator.cfn = None
    errs = list(rule.validate(validator, False, "ParentBucketWithBadCondition", {}))

    assert errs == [], f"Test without cfn got {errs!r}"


def test_sam_module_subresource_skipped(rule, validator):
    """Only true ``::MODULE`` sub-resources are suppressed from DependsOn
    existence checking.

    SAM-generated resources (``<id>Role``, ``<id>.Version``, ``<id>.Alias``,
    ``<id>Url``, ``<id><event>Permission``, ``<id>Stage``, ...) are modeled
    by exact logical ID in ``_inject_sam_implicit_resources``, so an
    ``AWS::Serverless::*`` logical ID is NOT a module prefix: a ``DependsOn``
    whose target merely starts with such a logical ID must still be
    validated and reported if the target does not exist.
    """
    # Add a SAM function and a real MODULE resource
    resources = dict(validator.context.resources)
    resources["MyFunc"] = Resource({"Type": "AWS::Serverless::Function"})
    resources["MyModule"] = Resource(
        {"Type": "My::Organization::Custom::MODULE"}
    )

    validator = validator.evolve(
        context=validator.context.evolve(
            path=Path(path=deque(["Resources", "MyResource", "DependsOn"])),
            resources=resources,
        )
    )

    # DependsOn the SAM function itself - still valid
    errs = list(rule.validate(validator, False, "MyFunc", {}))
    assert errs == [], "SAM function itself should be valid"

    # DependsOn a name that merely shares a SAM-function prefix must now
    # error - the SAM wildcard that previously suppressed this check has
    # been removed because it silently disabled E3005 for arbitrary
    # undefined references.
    errs = list(rule.validate(validator, False, "MyFuncAliaslive", {}))
    assert len(errs) == 1, "SAM prefix wildcard must not suppress E3005"
    assert "MyFuncAliaslive" in errs[0].message

    # DependsOn a ``::MODULE`` sub-resource is still skipped - the real
    # MODULE suppression path is unaffected.
    errs = list(rule.validate(validator, False, "MyModuleBucket", {}))
    assert errs == [], "MODULE sub-resource should be skipped"

    # DependsOn a completely unknown resource - should error
    errs = list(rule.validate(validator, False, "TotallyUnknown", {}))
    assert len(errs) == 1, "Unknown resource should error"
    assert "TotallyUnknown" in errs[0].message
