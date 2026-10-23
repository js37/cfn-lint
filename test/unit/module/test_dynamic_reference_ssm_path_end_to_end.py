"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

from unittest import TestCase

from cfnlint import lint_all


class TestDynamicReferenceSsmPathEndToEnd(TestCase):
    """End-to-end (decode -> runner -> rules) coverage for E1052.

    Guards against the regression where E1052 is registered but not wired
    to its parent rule (E1050), so unsupported {{resolve:ssm:...}}
    placements silently pass.
    """

    def test_ssm_dynamic_reference_in_export_name_is_reported(self):
        template = (
            'AWSTemplateFormatVersion: "2010-09-09"\n'
            "Resources:\n"
            "  MyTopic:\n"
            "    Type: AWS::SNS::Topic\n"
            "Outputs:\n"
            "  Out:\n"
            '    Value: "static"\n'
            "    Export:\n"
            '      Name: "{{resolve:ssm:MyParameter}}"\n'
        )
        matches = lint_all(template)
        rule_ids = [m.rule.id for m in matches]
        self.assertIn("E1052", rule_ids, f"Got {matches!r}")

    def test_ssm_dynamic_reference_in_output_value_is_allowed(self):
        template = (
            'AWSTemplateFormatVersion: "2010-09-09"\n'
            "Resources:\n"
            "  MyTopic:\n"
            "    Type: AWS::SNS::Topic\n"
            "Outputs:\n"
            "  Out:\n"
            '    Value: "{{resolve:ssm:MyParameter}}"\n'
        )
        matches = lint_all(template)
        rule_ids = [m.rule.id for m in matches]
        self.assertNotIn("E1052", rule_ids, f"Got {matches!r}")

    def test_ssm_dynamic_reference_in_resource_property_is_allowed(self):
        template = (
            'AWSTemplateFormatVersion: "2010-09-09"\n'
            "Resources:\n"
            "  MyTopic:\n"
            "    Type: AWS::SNS::Topic\n"
            "    Properties:\n"
            '      DisplayName: "{{resolve:ssm:MyParameter}}"\n'
        )
        matches = lint_all(template)
        rule_ids = [m.rule.id for m in matches]
        self.assertNotIn("E1052", rule_ids, f"Got {matches!r}")
