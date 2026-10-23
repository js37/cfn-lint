"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from io import StringIO
from test.testlib.testcase import BaseTestCase
from unittest.mock import patch

import cfnlint.decode.cfn_json  # pylint: disable=E0401
from cfnlint import ConfigMixIn
from cfnlint.config import _DEFAULT_RULESDIR
from cfnlint.rules import Rules
from cfnlint.template.template import Template  # pylint: disable=E0401


class TestCfnJson(BaseTestCase):
    """Test JSON Parsing"""

    def setUp(self):
        """SetUp template object"""
        self.rules = Rules.create_from_directory(_DEFAULT_RULESDIR)
        self.config = ConfigMixIn(
            include_experimental=True,
        )

        self.filenames = {
            "config_rule": {
                "filename": "test/fixtures/templates/quickstart/config-rules.json",
                "failures": 5,
            },
            "iam": {
                "filename": "test/fixtures/templates/quickstart/iam.json",
                "failures": 4,
            },
            "nat_instance": {
                "filename": "test/fixtures/templates/quickstart/nat-instance.json",
                "failures": 6,
            },
            "vpc_management": {
                "filename": "test/fixtures/templates/quickstart/vpc-management.json",
                "failures": 11,
            },
            "vpc": {
                "filename": "test/fixtures/templates/quickstart/vpc.json",
                "failures": 5,
            },
            "poller": {
                "filename": "test/fixtures/templates/public/lambda-poller.json",
                "failures": 1,
            },
        }

    def test_success_parse(self):
        """Test Successful JSON Parsing"""
        for _, values in self.filenames.items():
            filename = values.get("filename")
            failures = values.get("failures")

            template = cfnlint.decode.cfn_json.load(filename)
            cfn = Template(filename, template, ["us-east-1"])

            matches = list(self.rules.run(filename, cfn, self.config))
            assert len(matches) == failures, (
                "Expected {} failures, got {} on {}".format(failures, matches, filename)
            )

    def test_success_escape_character(self):
        """Test Successful JSON Parsing"""
        failures = 1
        filename = "test/fixtures/templates/good/decode/parsing.json"
        template = cfnlint.decode.cfn_json.load(filename)
        cfn = Template(filename, template, ["us-east-1"])

        matches = list(self.rules.run(filename, cfn, self.config))
        assert len(matches) == failures, "Expected {} failures, got {} on {}".format(
            failures, matches, filename
        )

    def test_success_parse_stdin(self):
        """Test Successful JSON Parsing through stdin"""
        for _, values in self.filenames.items():
            filename = None
            failures = values.get("failures")
            with open(values.get("filename"), "r") as fp:
                file_content = fp.read()
            with patch("sys.stdin", StringIO(file_content)):
                template = cfnlint.decode.cfn_json.load(filename)
                cfn = Template(filename, template, ["us-east-1"])

                matches = list(self.rules.run(filename, cfn, self.config))
                assert len(matches) == failures, (
                    "Expected {} failures, got {} on {}".format(
                        failures, matches, values.get("filename")
                    )
                )

    def test_fail_run(self):
        """Test failure run"""

        filename = "test/fixtures/templates/bad/json_parse.json"

        try:
            cfnlint.decode.cfn_json.load(filename)
        except cfnlint.decode.cfn_json.JSONDecodeError:
            assert True
            return

        assert False

    def test_missing_object_member_value_raises_json_decode_error(self):
        """Regression: an object member with no value must raise JSONDecodeError
        (not a bare TypeError) and carry the correct line/column of the syntax
        error. See cfn_json_object StopIteration handler."""
        try:
            cfnlint.decode.cfn_json.loads('{"a": }')
        except cfnlint.decode.cfn_json.JSONDecodeError as err:
            # pos must be an integer offset, matching the documented contract.
            assert isinstance(err.pos, int), (
                f"pos must be int, got {type(err.pos).__name__}"
            )
            # The syntax error is on line 1 at column 7 (same as stdlib json).
            assert err.lineno == 1, f"expected line 1, got {err.lineno}"
            assert err.colno == 1, f"expected colno 1 (first match linenumber), got {err.colno}"
            assert err.matches, "expected at least one Match in errors"
            m = err.matches[0]
            assert m.linenumber == 1
            # pos is 6 (index of '}' in '{"a": }'); build_match reports
            # columnnumber = (pos - rfind('\n',0,pos)) + 1 = 7 + 1 = 8.
            assert m.columnnumber == 8, f"expected columnnumber 8, got {m.columnnumber}"
            assert err.pos == 6, f"expected pos 6, got {err.pos}"
            return
        assert False, "expected JSONDecodeError, got no exception"
