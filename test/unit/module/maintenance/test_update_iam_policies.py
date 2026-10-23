"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json
import logging
from test.testlib.testcase import BaseTestCase
from unittest.mock import patch

import cfnlint.maintenance

LOGGER = logging.getLogger("cfnlint.maintenance")
LOGGER.addHandler(logging.NullHandler())


class TestUpdateIamPolicies(BaseTestCase):
    """Used for Testing Rules"""

    @patch("cfnlint.maintenance.get_url_content")
    @patch("cfnlint.maintenance.json.dump")
    def test_update_iam_policies(self, mock_json_dump, mock_content):
        """Success update iam policies"""

        services = [
            {
                "service": "foo",
                "url": (
                    "https://servicereference.us-east-1.amazonaws.com/v1/foo/foo.json"
                ),
            }
        ]

        cloudformation = {
            "Name": "cloudformation",
            "Actions": [
                {
                    "Name": "CreateStack",
                    "ActionConditionKeys": [
                        "aws:RequestTag/${TagKey}",
                        "aws:TagKeys",
                        "cloudformation:ResourceTypes",
                        "cloudformation:RoleArn",
                        "cloudformation:StackPolicyUrl",
                        "cloudformation:TemplateUrl",
                    ],
                    "Resources": [{"Name": "stack"}],
                }
            ],
            "Resources": [
                {
                    "Name": "stack",
                    "ARNFormats": [
                        "arn:${Partition}:cloudformation:${Region}:${Account}:stack/${StackName}/${Id}"
                    ],
                    "ConditionKeys": ["aws:ResourceTag/${TagKey}"],
                },
                {
                    "Name": "stackset",
                    "ARNFormats": [
                        "arn:${Partition}:cloudformation:${Region}:${Account}:${StackSetName}"
                    ],
                },
            ],
        }

        mock_content.side_effect = [
            json.dumps(services),
            json.dumps(cloudformation),
        ]

        with (
            patch("cfnlint.maintenance.tempfile.mkstemp") as mock_mkstemp,
            patch("cfnlint.maintenance.os.fdopen") as mock_fdopen,
            patch("cfnlint.maintenance.os.replace") as mock_replace,
        ):
            mock_mkstemp.return_value = (99, "/tmp/Policies.json.tmp")
            cfnlint.maintenance.update_iam_policies()
            mock_json_dump.assert_called_with(
                {
                    "foo": {
                        "Actions": {"createstack": {"Resources": ["stack"]}},
                        "Resources": {
                            "stack": {
                                "ARNFormats": [
                                    "arn:${Partition}:cloudformation:${Region}:${Account}:stack/.*"
                                ],
                                "ConditionKeys": ["aws:ResourceTag/${TagKey}"],
                            },
                            "stackset": {
                                "ARNFormats": [
                                    "arn:${Partition}:cloudformation:${Region}:${Account}:.*"
                                ]
                            },
                        },
                    }
                },
                mock_fdopen.return_value.__enter__.return_value,
                indent=1,
                separators=(",", ": "),
                sort_keys=True,
            )
            self.assertTrue(mock_replace.called)

    @patch("cfnlint.maintenance.get_url_content")
    def test_update_iam_policies_rejects_bad_url_scheme(self, mock_content):
        """A non-https url in the index response must be rejected."""

        services = [{"service": "foo", "url": "file:///etc/passwd"}]
        mock_content.side_effect = [json.dumps(services)]

        with self.assertRaises(ValueError):
            cfnlint.maintenance.update_iam_policies()

    @patch("cfnlint.maintenance.get_url_content")
    def test_update_iam_policies_rejects_bad_url_host(self, mock_content):
        """An https url on an unexpected host must be rejected."""

        services = [{"service": "foo", "url": "https://evil.example.com/foo.json"}]
        mock_content.side_effect = [json.dumps(services)]

        with self.assertRaises(ValueError):
            cfnlint.maintenance.update_iam_policies()
