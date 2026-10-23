"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import re

# Control characters that must be neutralized before being emitted to a
# terminal or CI log so attacker-authored template strings (for example a
# Parameters logical ID containing an ESC sequence) cannot repaint, erase
# or forge cfn-lint output. We strip the C0 range (0x00-0x1f) and DEL
# (0x7f) but preserve the common whitespace characters (TAB, LF and CR)
# because formatters rely on them for layout.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _escape_control_char(match):
    ch = match.group(0)
    return "\\x{0:02x}".format(ord(ch))


def sanitize(value):
    """Replace unsafe control characters in a string with a visible escape.

    Non-string values are returned unchanged so callers can safely pass
    optional attributes such as match.filename.
    """
    if not isinstance(value, str):
        return value
    return _CONTROL_CHAR_RE.sub(_escape_control_char, value)


class BaseFormatter:
    """Base Formatter class"""

    def _format(self, match):
        """Format the specific match"""

    def print_matches(self, matches, rules, config):
        """Output all the matches"""
        if not matches:
            return None

        # Output each match on a separate line by default
        output = []
        for match in matches:
            output.append(self._format(match))

        return "\n".join(output)
