"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from cfnlint.formatters.base import BaseFormatter


class ParseableFormatter(BaseFormatter):
    """Parseable Formatter"""

    def _format(self, match):
        """Format output"""
        formatstr = "{0}:{1}:{2}:{3}:{4}:{5}:{6}"
        return formatstr.format(
            self._sanitize_filename(match.filename),
            match.linenumber,
            match.columnnumber,
            match.linenumberend,
            match.columnnumberend,
            match.rule.id,
            self._sanitize_message(match.message),
        )
