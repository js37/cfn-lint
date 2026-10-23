"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from collections import deque

import pytest

from cfnlint.context import Path, create_context_for_template
from cfnlint.jsonschema import CfnTemplateValidator
from cfnlint.rules.functions.Base64 import Base64
from cfnlint.rules.functions.DynamicReferenceSecretsManagerPath import (
    DynamicReferenceSecretsManagerPath,
)
from cfnlint.rules.functions.DynamicReferenceSecureString import (
    DynamicReferenceSecureString,
)
from cfnlint.rules.functions.Join import Join
from cfnlint.rules.functions.Select import Select
from cfnlint.rules.functions.Sub import Sub
from cfnlint.template import Template


@pytest.fixture
def cfn():
    return Template(
        "",
        {"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket"}}},
        regions=["us-east-1"],
    )


def _make_validator(cfn, path, cfn_path=None):
    context = create_context_for_template(cfn).evolve(
        path=Path(path=deque(path), cfn_path=deque(cfn_path or []))
    )
    return CfnTemplateValidator(context=context, cfn=cfn)


def _wire(parent, *rules):
    for rule in rules:
        parent.child_rules[rule.id] = rule
    return parent


@pytest.fixture
def sub_rule():
    rule = Sub()
    _wire(rule, DynamicReferenceSecureString(), DynamicReferenceSecretsManagerPath())
    return rule


@pytest.fixture
def join_rule():
    rule = Join()
    _wire(rule, DynamicReferenceSecureString(), DynamicReferenceSecretsManagerPath())
    return rule


@pytest.fixture
def base64_rule():
    rule = Base64()
    _wire(rule, DynamicReferenceSecureString(), DynamicReferenceSecretsManagerPath())
    return rule


@pytest.fixture
def select_rule():
    rule = Select()
    _wire(rule, DynamicReferenceSecureString(), DynamicReferenceSecretsManagerPath())
    return rule


def _has_rule(errs, rule_id):
    return any(getattr(err.rule, "id", None) == rule_id for err in errs)


def test_sub_wraps_ssm_secure_in_output(sub_rule, cfn):
    validator = _make_validator(cfn, ["Outputs", "MyOutput", "Value"])
    instance = {"Fn::Sub": "x-" + "{{" + "resolve:ssm-secure:/db/pass" + "}}"}
    errs = list(sub_rule.fn_sub(validator, {"type": "string"}, instance, {}))
    assert _has_rule(errs, "E1027"), errs


def test_sub_wraps_secretsmanager_in_output(sub_rule, cfn):
    validator = _make_validator(cfn, ["Outputs", "MyOutput", "Value"])
    inner = "{{" + "resolve:secretsmanager:mysecret:SecretString:pw" + "}}"
    instance = {"Fn::Sub": "x-" + inner}
    errs = list(sub_rule.fn_sub(validator, {"type": "string"}, instance, {}))
    assert _has_rule(errs, "E1051"), errs


def test_sub_ssm_secure_in_allowed_resource_property(sub_rule, cfn):
    validator = _make_validator(
        cfn,
        path=["Resources", "MyDB", "Properties", "MasterUserPassword"],
        cfn_path=[
            "Resources",
            "AWS::RDS::DBInstance",
            "Properties",
            "MasterUserPassword",
        ],
    )
    inner = "{{" + "resolve:ssm-secure:MySecurePassword:1" + "}}"
    instance = {"Fn::Sub": "list-" + inner}
    errs = list(sub_rule.fn_sub(validator, {"type": "string"}, instance, {}))
    assert not _has_rule(errs, "E1027"), errs


def test_join_wraps_secretsmanager_in_output(join_rule, cfn):
    validator = _make_validator(cfn, ["Outputs", "MyOutput", "Value"])
    inner = "{{" + "resolve:secretsmanager:mysecret" + "}}"
    instance = {"Fn::Join": ["", [inner]]}
    errs = list(join_rule.fn_join(validator, {"type": "string"}, instance, {}))
    assert _has_rule(errs, "E1051"), errs


def test_base64_wraps_ssm_secure_in_output(base64_rule, cfn):
    validator = _make_validator(cfn, ["Outputs", "MyOutput", "Value"])
    inner = "{{" + "resolve:ssm-secure:/db/pass" + "}}"
    instance = {"Fn::Base64": inner}
    errs = list(base64_rule.fn_base64(validator, {"type": "string"}, instance, {}))
    assert _has_rule(errs, "E1027"), errs


def test_select_wraps_secretsmanager_in_output(select_rule, cfn):
    validator = _make_validator(cfn, ["Outputs", "MyOutput", "Value"])
    inner = "{{" + "resolve:secretsmanager:mysecret:SecretString:pw" + "}}"
    instance = {"Fn::Select": [0, [inner]]}
    errs = list(select_rule.fn_select(validator, {"type": "string"}, instance, {}))
    assert _has_rule(errs, "E1051"), errs
