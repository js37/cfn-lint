"""
Copyright (c) 2013 Julian Berman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

SPDX-License-Identifier: MIT
"""

# Code is taken from jsonschema package and adapted CloudFormation use
# https://github.com/python-jsonschema/jsonschema

from collections.abc import Mapping, Sequence

import regex as re

from cfnlint.helpers import FUNCTION_TRANSFORM, bool_compare


class Unset:
    """
    An as-of-yet unset attribute or unprovided default parameter.
    """

    def __repr__(self):
        return "<unset>"


def find_additional_properties(validator, instance, schema):
    """
    Return the set of additional properties for the given ``instance``.

    Weeds out properties that should have been validated by ``properties`` and
    / or ``patternProperties``.

    Assumes ``instance`` is dict-like already.
    """

    properties = schema.get("properties", {})
    patterns = "|".join(schema.get("patternProperties", {}))
    for property in instance:
        if (
            property == FUNCTION_TRANSFORM
            and FUNCTION_TRANSFORM in validator.context.functions
        ):
            continue
        if property not in properties:
            if validator.is_type(property, "string"):
                if patterns and re.search(patterns, property):
                    continue
            yield property


def custom_msg(validator, schema):
    """
    Create an error message for custom validation.
    """
    if not isinstance(schema, dict):
        return None
    messages = schema.get("message")
    if isinstance(messages, dict):
        return messages.get(validator)

    return None


def _mapping_equal(one, two):
    """
    Check if two mappings are equal using the semantics of `equal`.
    """
    if len(one) != len(two):
        return False
    return all(key in two and equal(value, two[key]) for key, value in one.items())


def _sequence_equal(one, two):
    """
    Check if two sequences are equal using the semantics of `equal`.
    """
    if len(one) != len(two):
        return False
    return all(equal(i, j) for i, j in zip(one, two))


def equal(one, two):
    """
    Check if two things are equal evading some Python type hierarchy semantics.

    Specifically in JSON Schema, evade `bool` inheriting from `int`,
    recursing into sequences to do the same.
    """
    # Handle boolean string comparisons (CloudFormation accepts "true"/"false" strings)
    if isinstance(one, (bool, str)) and isinstance(two, (bool, str)):
        # Check if either is a boolean string
        if (
            (isinstance(one, str) and one.lower() in ["true", "false"])
            or (isinstance(two, str) and two.lower() in ["true", "false"])
            or isinstance(one, bool)
            or isinstance(two, bool)
        ):
            return bool_compare(one, two)

    if isinstance(one, str) or isinstance(two, str):
        try:
            return str(one) == str(two)
        except ValueError:
            return False
    if isinstance(one, Sequence) and isinstance(two, Sequence):
        return _sequence_equal(one, two)
    if isinstance(one, Mapping) and isinstance(two, Mapping):
        return _mapping_equal(one, two)
    return unbool(one) == unbool(two)


def unbool(element, true=object(), false=object()):
    """
    A hack to make True and 1 and False and 0 unique for ``uniq``.
    """

    if element is True:
        return true
    elif element is False:
        return false
    return element


def _hashable(value):
    """
    Build a hashable canonical form of ``value`` that preserves the
    equivalence semantics of :func:`equal`:

    * Booleans and the strings ``"true"``/``"false"`` (any case) collapse to
      the same token, matching :func:`cfnlint.helpers.bool_compare`.
    * Numeric scalars share a canonical form with their ``str()`` rendering,
      matching the string branch of :func:`equal`.
    * Mappings and sequences are normalised recursively; mapping keys are
      sorted so order does not matter.

    The result is only used as a dictionary/``set`` key for duplicate
    detection, which turns the previous O(n^2) ``equal`` scan into an O(n)
    hash lookup.
    """
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, str):
        lowered = value.lower()
        if lowered == "true":
            return ("bool", True)
        if lowered == "false":
            return ("bool", False)
        return ("str", value)
    if isinstance(value, (int, float)):
        # ``equal`` treats numbers and their ``str()`` representation as
        # equivalent whenever one side is a string, so canonicalise through
        # ``str`` here as well.
        return ("str", str(value))
    if value is None:
        return ("none",)
    if isinstance(value, Mapping):
        return (
            "map",
            tuple(sorted((k, _hashable(v)) for k, v in value.items())),
        )
    if isinstance(value, Sequence):
        return ("seq", tuple(_hashable(v) for v in value))
    # Fallback for anything exotic: rely on the object's own hashability if
    # possible, otherwise its ``repr``.  This path is not reached for normal
    # template data, which is JSON-shaped.
    try:
        hash(value)
    except TypeError:
        return ("repr", repr(value))
    return ("obj", value)


def uniq(container):
    """
    Check if all of a container's elements are unique.

    Uses a hashed canonical form of each element (see :func:`_hashable`) so
    detection is O(n) rather than the previous O(n^2) ``equal`` scan, while
    preserving the string/bool/number equivalence semantics of :func:`equal`.
    """
    seen = set()
    for element in container:
        key = _hashable(element)
        if key in seen:
            return False
        seen.add(key)
    return True


def uniq_keys(container, keys):
    """
    Check if all of a container's elements are unique based on a key tuple.

    Uses a hashed canonical form of the extracted key tuple (see
    :func:`_hashable`) so detection is O(n) rather than the previous O(n^2)
    ``equal`` scan.  Elements that do not expose every key are skipped, as
    before.
    """
    seen = set()
    for item in container:
        try:
            key = tuple(_hashable(item[k]) for k in keys)
        except (KeyError, TypeError):
            continue
        if key in seen:
            return False
        seen.add(key)
    return True
