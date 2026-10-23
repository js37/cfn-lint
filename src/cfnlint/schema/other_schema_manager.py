"""
Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
import sys
from functools import lru_cache
from typing import TYPE_CHECKING, Any

import jsonpatch

from cfnlint.helpers import load_resource
from cfnlint.schema._exceptions import SchemaNotFoundError

# A valid dotted schema path component (Python identifier-like, no
# separators, no traversal). This prevents an override-spec `Patches` key
# from being used to escape the ``cfnlint.data.schemas`` package when it is
# split into a module name and ``<component>.json`` filename.
_SCHEMA_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9_]+$")

if TYPE_CHECKING:
    from cfnlint.schema._patch import SchemaPatch

LOGGER = logging.getLogger(__name__)


class _FileLocation:
    def __init__(self, path: list[str]):
        self.path_relative = os.path.join(
            os.path.dirname(__file__),
            "..",
            *path,
        )
        self.module = ".".join(["cfnlint"] + path[:])
        self.path = path


class OtherSchemaManager:
    def __init__(self) -> None:
        self._root = _FileLocation(
            [
                "data",
                "schemas",
            ]
        )

        self._schemas: dict[str, dict[str, Any]] = {}
        self._schema_modules: dict[str, Any] = {}
        self.reset()

    def reset(self) -> None:
        """
        Reset's the cache so specs can be reloaded.
        Important function when processing many templates
        and using spec patching
        """
        self._schemas = {}
        self.get_schema.cache_clear()

    def load_registry_schemas(self, path: str) -> None:
        """Load extra registry schemas from a directory

        Args:
            path (str): the directory to load schema files from
        Returns:
            None: None
        """
        for dirpath, _, filenames in os.walk(path):
            for filename in fnmatch.filter(filenames, "*.json"):
                with open(os.path.join(dirpath, filename), "r", encoding="utf-8") as fh:
                    schema: dict[str, dict[str, Any]] = json.load(fh)
                    self._schemas[path] = schema

    @staticmethod
    def _validate_schema_path(path: str) -> list[str]:
        """Validate a dotted schema path before it is used as a module and
        filename locator.

        Each dotted component must be a non-empty identifier-like string
        (``[A-Za-z0-9_]+``). This rejects path separators (``/`` / ``\\``),
        traversal segments (``..``), absolute-path components, and any
        other content that could escape the ``cfnlint.data.schemas``
        package when ``path`` is split into ``module.name`` plus
        ``<component>.json``.
        """
        if not isinstance(path, str) or not path:
            raise SchemaNotFoundError(path)
        path_parts = path.split(".")
        if len(path_parts) < 2:
            raise SchemaNotFoundError(path)
        for part in path_parts:
            if not _SCHEMA_PATH_COMPONENT.match(part):
                raise SchemaNotFoundError(path)
        return path_parts

    @lru_cache(maxsize=None)
    def get_schema(self, path: str) -> dict[str, Any]:
        """Get the provider resource schema and cache it to speed up future lookups

        Args:
            path: the path of the schema using the dot notation
        Returns:
            dict: returns the schema
        """

        schema = self._schemas.get(path)
        if schema is not None:
            return schema

        # Validate the dotted path before it reaches ``__import__`` or
        # ``load_resource``. Only identifier-like components are allowed,
        # which prevents keys such as ``other.functions./tmp/ci/secrets``
        # from being turned into an absolute filesystem read.
        path_parts = self._validate_schema_path(path)
        module_name = ".".join(path_parts[:-1])
        filename = f"{path_parts[-1]}.json"
        try:
            self._schema_modules[module_name] = __import__(
                f"{self._root.module}.{module_name}", fromlist=[""]
            )

            self._schemas[path] = load_resource(
                self._schema_modules[module_name],
                filename=filename,
            )
            return self._schemas[path]
        except SchemaNotFoundError:
            raise
        except Exception as e:
            raise SchemaNotFoundError(path) from e

    def patch(self, patch: SchemaPatch, region: str) -> None:
        """Patch the schemas as needed

        Args:
            patch: The patches to be applied to the schemas
        Returns:
            None: Returns when completed
        """

        for schema_path, patches in patch.patches.items():
            try:
                self.get_schema(path=schema_path)
            except SchemaNotFoundError:
                # Resource type doesn't exist in this region
                continue
            try:
                jsonpatch.JsonPatch(patches).apply(
                    self._schemas[schema_path], in_place=True
                )
            except Exception:
                # Do not echo the patch body or the exception message: both
                # can embed values from the schema document, which would
                # turn a patch failure into content disclosure. Only the
                # schema path (the attacker-chosen key) is logged.
                LOGGER.error("Error applying patch for %s", schema_path)
                sys.exit(1)


OTHER_SCHEMA_MANAGER: OtherSchemaManager = OtherSchemaManager()
