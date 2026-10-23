"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

Safe-matching helpers for regular expressions whose pattern and/or subject
come from untrusted CloudFormation templates or user-supplied custom-rule
files (CWE-1333: Inefficient Regular Expression Complexity).
"""

from __future__ import annotations

import logging
from typing import Any

import regex as re

LOGGER = logging.getLogger(__name__)

# Hard bounds applied to template-supplied regex evaluation. These values
# are conservative: real CloudFormation AllowedPattern / string property
# subjects are a few hundred characters at most. The timeout is well above
# the time a well-behaved match needs on a modern CPU, so legitimate rules
# are unaffected.
REGEX_SUBJECT_MAX_LEN = 4096
REGEX_MATCH_TIMEOUT = 1.0


def _coerce_subject(subject: Any) -> str:
    return subject if isinstance(subject, str) else str(subject)


def safe_regex_match(
    pattern: str,
    subject: Any,
    *,
    timeout: float = REGEX_MATCH_TIMEOUT,
    max_subject_len: int = REGEX_SUBJECT_MAX_LEN,
) -> "bool | None":
    """Return True or False for a bounded ``re.match(pattern, subject)``.

    Returns ``None`` when the pattern cannot be evaluated safely (compile
    error, catastrophic-backtracking timeout, or subject exceeds
    ``max_subject_len``). Callers should treat ``None`` as an undetermined
    result and skip the check.
    """
    text = _coerce_subject(subject)
    if len(text) > max_subject_len:
        LOGGER.debug(
            "Skipping template-supplied regex %r on %d-char subject (cap %d)",
            pattern,
            len(text),
            max_subject_len,
        )
        return None
    try:
        return re.match(pattern, text, timeout=timeout) is not None
    except TimeoutError as ex:
        LOGGER.debug(
            'Regex pattern "%s" exceeded %.3fs timeout on subject of length %d: %s',
            pattern,
            timeout,
            len(text),
            ex,
        )
        return None
    except re.error as ex:
        LOGGER.debug(
            'Regex pattern "%s" is not supported by Python: %s',
            pattern,
            ex,
        )
        return None
    except TypeError:
        # Older versions of the ``regex`` module may not accept the
        # ``timeout`` keyword. Fall back to a length-capped unbounded
        # match as a safety net; this branch should not run with the
        # pinned dependency.
        try:
            return re.match(pattern, text) is not None
        except re.error as ex:
            LOGGER.debug(
                'Regex pattern "%s" is not supported by Python: %s',
                pattern,
                ex,
            )
            return None
