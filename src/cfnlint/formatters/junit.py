"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from cfnlint.formatters.base import BaseFormatter


class JUnitFormatter(BaseFormatter):
    """JUnit-style Reports"""

    def _failure_format(self, match):
        """Format output of a failure"""
        formatstr = "{0} at {1}:{2}:{3}"
        return formatstr.format(
            match.message, match.filename, match.linenumber, match.columnnumber
        )

    def print_matches(self, matches, rules, config):
        """Output all the matches"""

        try:
            from junit_xml import TestCase, TestSuite, to_xml_report_string
        except ImportError as e:
            raise ImportError("Missing optional dependencies junit") from e

        if not rules:
            return None

        # Group matches by rule id so we emit a failure test case for every
        # match, even when the rule was never executed by Rules.run (for
        # example E0000 parse errors, E0001 transform errors, or any other
        # match produced outside of rule execution).
        matches_by_rule_id: dict = {}
        for match in matches:
            matches_by_rule_id.setdefault(match.rule.id, []).append(match)

        test_cases = []
        reported_rule_ids = set()
        for rule in rules.values():
            if not rule.id:
                continue
            rule_matches = matches_by_rule_id.get(rule.id)
            if rule_matches:
                test_case = TestCase(
                    name=f"{rule.id} {rule.shortdesc}",
                    allow_multiple_subelements=True,
                    url=rule.source_url,
                )
                for match in rule_matches:
                    test_case.add_failure_info(
                        message=self._failure_format(match),
                        failure_type=match.message,
                    )
                test_cases.append(test_case)
                reported_rule_ids.add(rule.id)
            elif rule.id not in rules.used_rules:
                test_case = TestCase(name=f"{rule.id} {rule.shortdesc}")
                if rule.experimental:
                    test_case.add_skipped_info(
                        message="Experimental rule - not enabled"
                    )
                else:
                    test_case.add_skipped_info(message="Ignored rule")
                test_cases.append(test_case)
                reported_rule_ids.add(rule.id)
            else:
                # Rule was executed but produced no matches: emit an empty
                # (passing) test case so the report accounts for it.
                test_case = TestCase(
                    name=f"{rule.id} {rule.shortdesc}",
                    allow_multiple_subelements=True,
                    url=rule.source_url,
                )
                test_cases.append(test_case)
                reported_rule_ids.add(rule.id)

        # Any rule id that appears in matches but is not known to the rules
        # collection still needs to surface as a failure, otherwise the
        # report would silently drop those matches.
        for rule_id, rule_matches in matches_by_rule_id.items():
            if rule_id in reported_rule_ids:
                continue
            first = rule_matches[0]
            shortdesc = getattr(first.rule, "shortdesc", "") or ""
            name = f"{rule_id} {shortdesc}".strip() if rule_id else shortdesc
            test_case = TestCase(
                name=name or "unknown",
                allow_multiple_subelements=True,
                url=getattr(first.rule, "source_url", None),
            )
            for match in rule_matches:
                test_case.add_failure_info(
                    message=self._failure_format(match),
                    failure_type=match.message,
                )
            test_cases.append(test_case)

        test_suite = TestSuite("CloudFormation Lint", test_cases)

        return to_xml_report_string([test_suite], prettyprint=True)
