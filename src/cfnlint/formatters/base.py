"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import re

# Characters that can split, forge or corrupt records in text-based
# formatter output (parseable, default/pretty, JUnit XML attributes). This
# covers the C0 control range, DEL and the Unicode line/paragraph
# separators U+2028/U+2029, all of which are treated as line terminators
# by common consumers (``str.splitlines()``, Python's universal-newline
# file reader, many CI log parsers) and most of which are also illegal in
# XML 1.0. ``\n`` is intentionally included so a lone ``\r`` or embedded
# ``\n`` cannot inject an additional record.
_UNSAFE_TEXT_CHARS = re.compile("[\x00-\x1f\x7f\u2028\u2029]")


class BaseFormatter:
    """Base Formatter class"""

    @staticmethod
    def _sanitize_message(message):
        """Neutralise control characters that could forge extra records.

        Replaces every character that acts as a line terminator or is
        otherwise unsafe to embed in a line-oriented or XML text format
        with a single space. Non-string inputs are returned unchanged so
        that callers can safely pass through ``None``.
        """
        if not isinstance(message, str):
            return message
        return _UNSAFE_TEXT_CHARS.sub(" ", message)

    @staticmethod
    def _sanitize_filename(filename):
        """Neutralise control characters and the parseable field separator.

        In addition to the control characters handled by
        :meth:`_sanitize_message`, the colon -- which is the field
        separator of the parseable format -- is replaced so a repository
        file name containing a colon or a newline cannot corrupt or forge
        records. Non-string inputs are returned unchanged.
        """
        if not isinstance(filename, str):
            return filename
        return _UNSAFE_TEXT_CHARS.sub(" ", filename).replace(":", "_")

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
