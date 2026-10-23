"""
Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Iterator

import cfnlint.runner.deployment_file.deployment_types
from cfnlint.config import ConfigMixIn
from cfnlint.context.parameters import ParameterSet
from cfnlint.decode import decode
from cfnlint.rules import Match, RuleMatch
from cfnlint.rules.deployment_files.Configuration import Configuration
from cfnlint.runner.deployment_file.deployment import DeploymentFileData

LOGGER = logging.getLogger(__name__)

# Glob metacharacters that must not appear in a template-file-path sourced
# from a deployment file. If any of these are present, `glob.glob` would
# treat the value as a pattern and could enumerate files on the host.
_GLOB_METACHARS = ("*", "?", "[")


def _validate_template_file_path(
    template_file_path: str, deployment_file: str
) -> tuple[Path | None, str | None]:
    """Validate a ``template-file-path`` value from a deployment file.

    The value is untrusted (the deployment file may be checked in by a
    repository contributor whose privilege level is lower than the operator
    running cfn-lint). It must therefore be constrained so that it cannot
    point cfn-lint at files outside of the current working directory and
    cannot be used as a glob pattern that enumerates the host filesystem.

    Returns ``(path, None)`` on success or ``(None, error_message)`` on
    failure. The returned path is relative to the current working directory.
    """

    if any(ch in template_file_path for ch in _GLOB_METACHARS):
        return None, (
            f"Template file path {template_file_path!r} contains "
            "glob metacharacters, which are not allowed"
        )

    # Reject absolute paths (POSIX and Windows forms, including drive
    # letters and UNC paths) regardless of the host OS.
    if (
        os.path.isabs(template_file_path)
        or PurePosixPath(template_file_path).is_absolute()
        or PureWindowsPath(template_file_path).is_absolute()
    ):
        return None, (
            f"Template file path {template_file_path!r} must be a relative path"
        )

    # Reject explicit parent-directory traversal segments. We check the raw
    # value before resolution so that even values that happen to resolve
    # back inside the root (e.g. ``a/../b``) are rejected.
    parts = PurePosixPath(template_file_path.replace("\\", "/")).parts
    if any(part == ".." for part in parts):
        return None, (
            f"Template file path {template_file_path!r} must not contain "
            "'..' path segments"
        )

    root = Path.cwd().resolve()
    try:
        resolved = (root / template_file_path).resolve()
        template_path = resolved.relative_to(root)
    except ValueError:
        return None, (
            f"Template file path {template_file_path!r} resolves outside "
            "of the current working directory"
        )

    return template_path, None


def _parse_deployment_file(
    filename: str,
) -> DeploymentFileData | list[Match]:
    data, matches = decode(filename)

    if data is None:
        return matches

    all_matches: list[RuleMatch] = []
    for plugin in cfnlint.runner.deployment_file.deployment_types.__all__:
        deployment_data, deployment_matches = getattr(
            cfnlint.runner.deployment_file.deployment_types, plugin
        )(data)
        if deployment_matches:
            all_matches.extend(deployment_matches)
            continue

        return deployment_data  # type: ignore

    for match in all_matches:
        LOGGER.debug(
            f"While tring to process deployment file got error: {match.message}"
        )

    return [
        Match(
            linenumber=1,
            columnnumber=1,
            linenumberend=1,
            columnnumberend=1,
            filename=filename,
            message=f"Deployment file {filename!r} is not supported",
            rule=Configuration(),
        )
    ]


def expand_deployment_files(
    config: ConfigMixIn,
) -> Iterator[tuple[ConfigMixIn | None, list[Match]]]:
    """
    Run the deployment files specified in the configuration.

    Args:
        config (ConfigMixIn): The configuration object containing
        settings for the deployment file scan.

    Yields:

    """

    deployments: dict[str, list[ParameterSet]] = {}
    for deployment_file in config.deployment_files:
        deployment_data = _parse_deployment_file(deployment_file)

        if not isinstance(deployment_data, DeploymentFileData):
            yield None, deployment_data
            continue

        template_path, error_message = _validate_template_file_path(
            deployment_data.template_file_path, deployment_file
        )
        if template_path is None:
            LOGGER.debug(error_message)
            yield None, [
                Match(
                    linenumber=1,
                    columnnumber=1,
                    linenumberend=1,
                    columnnumberend=1,
                    filename=deployment_file,
                    message=error_message or "Invalid template-file-path",
                    rule=Configuration(),
                )
            ]
            continue

        if str(template_path) in deployments:
            deployments[str(template_path)].append(
                ParameterSet(deployment_file, deployment_data.parameters)
            )
        else:
            deployments[str(template_path)] = [
                ParameterSet(deployment_file, deployment_data.parameters)
            ]

    for path, parameter_sets in deployments.items():
        template_config = config.evolve(
            templates=[path],
            parameters=parameter_sets,
            deployment_files=[],
        )
        yield template_config, []
