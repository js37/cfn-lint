"""
Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
from typing import Any, Iterator, Mapping

from cfnlint.config import ConfigMixIn
from cfnlint.context.parameters import ParameterSet
from cfnlint.decode.decode import decode
from cfnlint.rules import Match
from cfnlint.rules.parameter_files.Configuration import Configuration

LOGGER = logging.getLogger(__name__)


def _not_supported_match(filename: str) -> list[Match]:
    return [
        Match(
            linenumber=1,
            columnnumber=1,
            linenumberend=1,
            columnnumberend=1,
            filename=filename,
            message=f"Parameter file {filename!r} is not supported",
            rule=Configuration(),
        )
    ]


def _parse_parameter_file(
    filename: str,
) -> dict[str, Any] | list[Match]:
    data, matches = decode(filename)

    if data is None:
        return matches

    # The parameter file must be a list of mappings. Anything else
    # (mapping, scalar, etc.) is not a supported parameter file shape
    # and must produce a clean Match rather than a traceback.
    if not isinstance(data, list):
        return _not_supported_match(filename)

    key = "ParameterKey"
    value = "ParameterValue"
    parameters: dict[str, Any] = {}
    for parameter in data:
        if not isinstance(parameter, Mapping):
            return _not_supported_match(filename)
        if not all(p in parameter for p in [key, value]):
            return _not_supported_match(filename)

        parameter_key = parameter.get(key)
        # ParameterKey is used as a dict key; it must be a string.
        # Non-string / unhashable values (e.g. a mapping or sequence)
        # would otherwise raise TypeError below.
        if not isinstance(parameter_key, str):
            return _not_supported_match(filename)

        parameters[parameter_key] = parameter.get(value)

    return parameters


def expand_parameter_files(
    config: ConfigMixIn,
) -> Iterator[tuple[ConfigMixIn | None, list[Match]]]:
    """
    Expands parameter files into an evolved config

    Args:
        config (ConfigMixIn): The configuration object containing
        settings for the deployment file scan.

    Yields:

    """

    parameters: list[ParameterSet] = []
    for parameter_file in config.parameter_files:
        try:
            parameter_data = _parse_parameter_file(parameter_file)
        except Exception as e:  # pylint: disable=broad-except
            LOGGER.debug(
                "Unexpected error while parsing parameter file %r: %s",
                parameter_file,
                e,
            )
            yield None, _not_supported_match(parameter_file)
            continue

        if not isinstance(parameter_data, dict):
            yield None, parameter_data
            continue

        parameters.append(ParameterSet(parameter_file, parameter_data))

    if parameters:
        parameters_config = config.evolve(
            parameters=parameters,
            deployment_files=[],
        )
        yield parameters_config, []
