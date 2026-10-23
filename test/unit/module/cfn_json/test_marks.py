"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from test.testlib.testcase import BaseTestCase

import cfnlint.decode.cfn_json  # pylint: disable=E0401
import cfnlint.decode.cfn_yaml  # pylint: disable=E0401
from cfnlint.decode.cfn_json import (
    find_indexes,
    get_beg_end_mark,
    largest_less_than,
)


class TestCfnJsonMarks(BaseTestCase):
    """Test that cfn_json source positions are well-formed and match the
    cfn_yaml decoder's positions for the equivalent document."""

    MULTI_LINE_JSON = (
        '{\n'
        '  "Resources": {\n'
        '    "A": {\n'
        '      "Type": "AWS::S3::Bucket"\n'
        '    }\n'
        '  }\n'
        '}\n'
    )

    def _collect_marks(self, obj):
        """Walk a decoded mapping and collect (key, start, end) tuples."""
        marks = []

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if hasattr(key, "start_mark"):
                        marks.append(
                            (
                                str(key),
                                (key.start_mark.line, key.start_mark.column),
                                (key.end_mark.line, key.end_mark.column),
                            )
                        )
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(obj)
        return marks

    def test_largest_less_than_binary_search(self):
        """largest_less_than must return the largest newline index strictly
        less than pos, driven solely by pos."""
        indexes = [1, 10, 20, 30]
        self.assertEqual(largest_less_than(indexes, 20), 10)
        self.assertEqual(largest_less_than(indexes, 25), 20)
        self.assertEqual(largest_less_than(indexes, 0), -1)
        self.assertEqual(largest_less_than(indexes, 1), -1)
        self.assertEqual(largest_less_than([], 5), -1)
        # Legacy third positional argument is accepted for compatibility.
        self.assertEqual(largest_less_than(indexes, 25, 1), 20)

    def test_get_beg_end_mark_is_non_negative_and_ordered(self):
        """Marks must be non-negative and end must not precede start."""
        indexes = find_indexes(self.MULTI_LINE_JSON)
        start = self.MULTI_LINE_JSON.index('"Resources"')
        end = start + len('"Resources"')
        beg, end_mark = get_beg_end_mark(start, end, indexes)
        self.assertGreaterEqual(beg.line, 0)
        self.assertGreaterEqual(beg.column, 0)
        self.assertGreaterEqual(end_mark.line, 0)
        self.assertGreaterEqual(end_mark.column, 0)
        self.assertGreaterEqual(end_mark.line, beg.line)
        if end_mark.line == beg.line:
            self.assertGreaterEqual(end_mark.column, beg.column)

    def test_marks_match_yaml_decoder(self):
        """The marks produced by cfn_json for a multi-line JSON document must
        agree with the marks produced by cfn_yaml for the equivalent document
        (JSON is a subset of YAML, so the same text can be decoded with either
        decoder). The line numbers must match exactly; column numbers must be
        well-formed (non-negative) and no end mark may precede its start.
        """
        json_doc = cfnlint.decode.cfn_json.loads(self.MULTI_LINE_JSON)
        yaml_doc = cfnlint.decode.cfn_yaml.loads(self.MULTI_LINE_JSON)

        json_marks = self._collect_marks(json_doc)
        yaml_marks = self._collect_marks(yaml_doc)

        # Same set of keys, in the same order.
        self.assertEqual(
            [k for (k, _, _) in json_marks],
            [k for (k, _, _) in yaml_marks],
        )

        # Line numbers must agree between the two decoders.
        for (jk, js, je), (yk, ys, ye) in zip(json_marks, yaml_marks):
            self.assertEqual(jk, yk)
            self.assertEqual(
                js[0], ys[0],
                f"start line mismatch for {jk}: json={js} yaml={ys}",
            )
            self.assertEqual(
                je[0], ye[0],
                f"end line mismatch for {jk}: json={je} yaml={ye}",
            )
            # Columns are non-negative and end is not before start.
            self.assertGreaterEqual(js[1], 0, jk)
            self.assertGreaterEqual(je[1], 0, jk)
            self.assertGreaterEqual(je[0], js[0], jk)

    def test_no_negative_or_inverted_marks_regression(self):
        """Regression: previously end marks for keys in multi-line JSON
        documents could be negative or precede the start mark."""
        decoded = cfnlint.decode.cfn_json.loads(self.MULTI_LINE_JSON)
        for key_text, start, end in self._collect_marks(decoded):
            self.assertGreaterEqual(start[0], 0, key_text)
            self.assertGreaterEqual(start[1], 0, key_text)
            self.assertGreaterEqual(end[0], 0, key_text)
            self.assertGreaterEqual(end[1], 0, key_text)
            self.assertGreaterEqual(end[0], start[0], key_text)
            if end[0] == start[0]:
                self.assertGreaterEqual(end[1], start[1], key_text)
