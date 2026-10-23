"""
Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Sequence

from cfnlint.helpers import (
    REGIONS,
    get_cache_dir,
    get_url_content,
    get_url_metadata,
    get_url_retrieve,
    save_metadata,
    url_has_newer_version,
)
from cfnlint.schema._exceptions import ResourceNotFoundError
from cfnlint.schema._getatts import AttributeDict
from cfnlint.schema._lock import file_lock
from cfnlint.schema._schema import Schema

if TYPE_CHECKING:
    from cfnlint.schema._patch import SchemaPatch

LOGGER = logging.getLogger(__name__)

_ENHANCED_SCHEMAS_URL = (
    "https://github.com/aws-cloudformation/"
    "resource-provider-enhanced-schemas/releases/download/latest/schemas-cfn-lint.zip"
)
_VERSION_URL = (
    "https://github.com/aws-cloudformation/"
    "resource-provider-enhanced-schemas/releases/download/latest/version.json"
)

_MODULE_SCHEMA = Schema(
    {"additionalProperties": True, "type": "object", "typeName": "Module"}
)


class ProviderSchemaManager:
    def __init__(
        self,
        providers_dir: Path | None = None,
        resources_dir: Path | None = None,
    ) -> None:
        if providers_dir or resources_dir:
            _cache = Path(get_cache_dir())
            self._providers_dir = providers_dir or _cache / "providers"
            self._resources_dir = resources_dir or _cache / "resources"
        else:
            self._providers_dir, self._resources_dir = self._resolve_schema_dirs()
        self._registry_schemas: dict[str, Schema] = {}
        self._provider_schema_modules: dict[str, dict[str, str]] = {}
        self._sam_schema_module: dict[str, str] | None = None
        self.reset()

    @staticmethod
    def _read_schema_date(directory: Path) -> str:
        """Read schema_date from a version.json file.

        Returns the raw string so callers may log or compare it. Use
        :meth:`_parse_schema_date` to obtain an orderable value.
        """
        version_file = directory / "version.json"
        try:
            with open(version_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    return ""
                result = data.get("schema_date", "")
                if not isinstance(result, str):
                    return ""
                return result
        except (OSError, json.JSONDecodeError):
            return ""

    @staticmethod
    def _parse_schema_date(value: str) -> datetime | None:
        """Parse ``schema_date`` into a comparable ``datetime``.

        The cache's ``version.json`` is unauthenticated local input, so
        comparing the raw string with ``>`` lets an attacker-chosen value
        such as ``"zzz"`` beat any genuine ISO-8601 timestamp. Parsing to
        a real ordered type closes that avenue: non-conforming values
        return ``None`` and are treated as older than any parseable date.
        """
        if not isinstance(value, str) or not value:
            return None
        # Accept the trailing ``Z`` (UTC) that ``update()`` writes.
        candidate = value.strip()
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(candidate)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _cache_dir_is_trustworthy(cache_dir: Path) -> bool:
        """Return True when the cache directory is safe to trust.

        On POSIX we require the directory to be owned by the invoking
        user and not group- or world-writable (unless the sticky bit is
        set, which still prevents cross-user tampering). A missing
        directory is trivially trustworthy (nothing to poison yet). On
        Windows we fall back to accepting the directory because POSIX
        ownership/mode semantics do not apply; defence-in-depth there
        depends on the manifest/parse hardening below.
        """
        try:
            st = os.stat(cache_dir)
        except FileNotFoundError:
            return True
        except OSError:
            return False

        if sys.platform == "win32":
            return True

        try:
            if st.st_uid != os.geteuid():
                return False
        except AttributeError:  # pragma: no cover - non-POSIX fallback
            return True

        mode = st.st_mode
        # Group- or world-writable without sticky bit means another
        # principal on the host can replace cache contents.
        if (mode & (stat.S_IWGRP | stat.S_IWOTH)) and not (mode & stat.S_ISVTX):
            return False
        return True

    @staticmethod
    def _resolve_schema_dirs() -> tuple[Path, Path]:
        """Determine which schema directory to use.

        Precedence:
        1. If the cache directory is not trustworthy (wrong owner or
           group/world-writable) it is ignored entirely and the bundled
           corpus is used when available.
        2. If both bundled and cache exist, use whichever records a
           strictly newer, parseable ``schema_date``. An unparseable or
           missing cache ``schema_date`` is treated as older than any
           parseable bundled value, so a poisoned ``{"schema_date":
           "zzz"}`` can never outrank the bundled corpus.
        3. If only bundled exists, use bundled.
        4. If only cache exists, use cache.
        5. If neither exists, use cache (auto-download will populate it).

        The selected corpus is logged so a cache takeover is observable.
        """
        _pkg_data = Path(os.path.dirname(__file__), "..", "data", "schemas")
        _pkg_providers = _pkg_data / "providers"
        _cache = Path(get_cache_dir())
        _cache_providers = _cache / "providers"

        bundled_exists = _pkg_providers.exists() and any(_pkg_providers.glob("*.json"))
        cache_exists = _cache_providers.exists() and any(
            _cache_providers.glob("*.json")
        )

        cache_trusted = ProviderSchemaManager._cache_dir_is_trustworthy(_cache)
        if cache_exists and not cache_trusted:
            LOGGER.warning(
                "Ignoring schema cache at %s: directory is not owned by the "
                "current user or is group/world-writable",
                _cache,
            )
            cache_exists = False

        if bundled_exists and cache_exists:
            bundled_raw = ProviderSchemaManager._read_schema_date(_pkg_data)
            cache_raw = ProviderSchemaManager._read_schema_date(_cache)
            bundled_parsed = ProviderSchemaManager._parse_schema_date(bundled_raw)
            cache_parsed = ProviderSchemaManager._parse_schema_date(cache_raw)

            # An unparseable cache date is treated as older than any
            # parseable bundled date. If the bundled date is also
            # unparseable we keep bundled (packaged corpus is signed by
            # the release pipeline, cache is not).
            use_cache = (
                cache_parsed is not None
                and bundled_parsed is not None
                and cache_parsed > bundled_parsed
            )
            if use_cache:
                LOGGER.info(
                    "Using cache schema corpus at %s (schema_date=%s, "
                    "bundled schema_date=%s)",
                    _cache,
                    cache_raw,
                    bundled_raw,
                )
                return _cache / "providers", _cache / "resources"
            LOGGER.info(
                "Using bundled schema corpus (schema_date=%s, "
                "cache schema_date=%s)",
                bundled_raw,
                cache_raw,
            )
            return _pkg_providers, _pkg_data / "resources"

        if bundled_exists:
            LOGGER.info("Using bundled schema corpus at %s", _pkg_providers)
            return _pkg_providers, _pkg_data / "resources"

        LOGGER.info("Using cache schema corpus at %s", _cache)
        return _cache / "providers", _cache / "resources"

    def reset(self) -> None:
        """
        Reset's the cache so specs can be reloaded.
        Important function when processing many templates
        and using spec patching
        """
        self._schemas: dict[str, dict[str, Schema]] = {}
        for region in REGIONS:
            self._schemas[region] = {}
        self._removed_types: list[str] = []
        self._provider_schema_modules = {}
        self._sam_schema_module = None
        self.get_resource_schema.cache_clear()
        self.get_resource_types.cache_clear()
        self.get_type_getatts.cache_clear()

    def _load_sam_module(self) -> dict[str, str]:
        """Load the SAM provider mapping from sam.json.

        SAM resource types are region-independent and stored in a
        separate pointer file from the per-region provider files.

        Returns:
            Dict mapping SAM resource type to schema hash
        """
        if self._sam_schema_module is None:
            sam_file = self._providers_dir / "sam.json"
            try:
                with open(sam_file, "r", encoding="utf-8") as f:
                    self._sam_schema_module = json.load(f)
            except FileNotFoundError:
                self._sam_schema_module = {}
        return self._sam_schema_module

    def _load_provider_module(self, region: str) -> dict[str, str]:
        """Load the provider mapping for a region from JSON.

        Falls back to us-east-1 if the region file is not available.
        Merges SAM resource types from sam.json.

        Args:
            region: Region name (e.g. 'us-east-1')
        Returns:
            Dict mapping resource type to schema hash
        """
        if region not in self._provider_schema_modules:
            if not (self._providers_dir / "us-east-1.json").exists():
                self.update(force=False)
            provider_file = self._providers_dir / f"{region}.json"
            if not provider_file.exists():
                provider_file = self._providers_dir / "us-east-1.json"
            try:
                with open(provider_file, "r", encoding="utf-8") as f:
                    self._provider_schema_modules[region] = json.load(f)
            except FileNotFoundError:
                self._provider_schema_modules[region] = {}
            self._provider_schema_modules[region].update(self._load_sam_module())
        return self._provider_schema_modules[region]

    def load_registry_schemas(self, path: str) -> None:
        """Load extra registry schemas from a directory

        Args:
            path (str): the directory to load schema files from
        Returns:
            None: None
        """
        for dirpath, _, filenames in os.walk(path):
            for filename in filenames:
                if not filename.endswith(".json"):
                    continue
                with open(os.path.join(dirpath, filename), "r", encoding="utf-8") as fh:
                    schema = Schema(json.load(fh))
                    self._registry_schemas[schema.type_name] = schema

    def get_resource_schemas_by_regions(
        self, resource_type: str, regions: Sequence[str]
    ) -> Iterator[tuple[list[str], Schema]]:
        """
        Get unique schemas with their associated regions

        Args:
            resource_type (str): the :: version of the resource type
            regions (Sequence[str]): the regions in which we want schems for
        Returns:
            Iterator[tuple[list[str], Schema]]: the unique schemas with
              their associated regions
        """
        # Match get_resource_schema: registry schemas are looked up before
        # the type is normalized, so a registry "::MODULE" type keeps its
        # own schema.
        is_registry_type = resource_type in self._registry_schemas
        if not is_registry_type:
            resource_type = self._normalize_resource_type(resource_type)

        hash_to_regions: dict[str, list[str]] = {}
        hash_to_schema: dict[str, Schema] = {}

        for region in regions:
            if is_registry_type:
                # Registry schemas are not in any region's provider mapping,
                # and one schema covers every region.
                schema_hash: str | None = resource_type
            else:
                provider_types = self._load_provider_module(region)
                schema_hash = provider_types.get(resource_type)

            if not schema_hash:
                continue

            if schema_hash not in hash_to_regions:
                try:
                    schema = self.get_resource_schema(region, resource_type)
                    hash_to_regions[schema_hash] = []
                    hash_to_schema[schema_hash] = schema
                except ResourceNotFoundError:
                    continue

            hash_to_regions[schema_hash].append(region)

        for schema_hash, region_list in hash_to_regions.items():
            yield region_list, hash_to_schema[schema_hash]

    def _normalize_resource_type(self, resource_type: str) -> str:
        """
        Normalize the resource type to the correct format

        Args:
            resource_type (str): the :: version of the resource type
        Returns:
            str: the normalized resource type
        """
        if resource_type.startswith("Custom::"):
            resource_type = "AWS::CloudFormation::CustomResource"
        if resource_type.endswith("::MODULE"):
            resource_type = "Module"

        return resource_type

    @lru_cache(maxsize=None)
    def get_resource_schema(self, region: str, resource_type: str) -> Schema:
        """Get the provider resource schema and cache it to speed up future lookups

        Args:
            region (str): the region in which do get the provider schema for
            resource_type (str): the :: version of the resource type
        Returns:
            dict: returns the schema
        """
        if resource_type not in self._registry_schemas:
            resource_type = self._normalize_resource_type(resource_type)

        if resource_type in self._removed_types:
            raise ResourceNotFoundError(resource_type, region)

        if resource_type == "Module":
            return _MODULE_SCHEMA

        schema = self._schemas[region].get(resource_type)
        if schema is not None:
            return schema

        if resource_type in self._registry_schemas:
            self._schemas[region][resource_type] = self._registry_schemas[resource_type]
            return self._schemas[region][resource_type]

        provider_types = self._load_provider_module(region)
        schema_hash = provider_types.get(resource_type)

        if not schema_hash:
            raise ResourceNotFoundError(resource_type, region)

        try:
            schema_file = self._resources_dir / f"{schema_hash}.json"
            with open(schema_file, "r", encoding="utf-8") as f:
                self._schemas[region][resource_type] = Schema(json.load(f))
            return self._schemas[region][resource_type]
        except Exception as e:
            raise ResourceNotFoundError(resource_type, region) from e

    @lru_cache(maxsize=None)
    def get_resource_types(self, region: str) -> list[str]:
        """Get the resource types for a region

        Args:
            region (str): the region in which to get the resource types for
        Returns:
            list[str]: returns a list of resource types
        """
        provider_types = self._load_provider_module(region)

        resource_types: list[str] = []
        resource_types.extend(
            rt for rt in provider_types.keys() if rt not in self._removed_types
        )
        resource_types.extend(list(self._registry_schemas.keys()))

        return resource_types

    def update(self, force: bool) -> int:
        """Update schemas from the enhanced schemas repository.

        Uses file locking to prevent concurrent processes from corrupting the
        cache. Extracts to a temporary directory and atomically replaces the
        active cache directories.

        Args:
            force (bool): force the schemas to be downloaded
        Returns:
            int: exit code (0=success, 2=failure)
        """
        # url_has_newer_version() performs a network HEAD request. URLError is
        # an OSError subclass, so wrap it here — otherwise a network failure
        # would surface later as a misleading lock-acquisition error.
        # `force` is evaluated first so a --force update bypasses the network
        # check entirely (matches the short-circuit order in _update_locked).
        try:
            if not (force or url_has_newer_version(_ENHANCED_SCHEMAS_URL)):
                LOGGER.info("Schemas are up to date")
                return 0
        except OSError as e:
            LOGGER.error("Failed to check schema version: %s", e)
            return 2

        _cache = Path(get_cache_dir())
        lock_path = _cache / ".update.lock"

        try:
            with file_lock(lock_path):
                return self._update_locked(_cache, force)
        except TimeoutError as e:
            LOGGER.error("Timed out waiting for schema cache lock: %s", e)
            return 2
        except OSError as e:
            # Raised by file_lock while creating/locking the lock file
            LOGGER.error("Failed to acquire schema cache lock: %s", e)
            return 2
        except Exception as e:  # pragma: no cover
            LOGGER.error("Schema update failed: %s", e)
            return 2

    def _update_locked(self, cache_dir: Path, force: bool) -> int:
        """Perform the actual update while holding the lock.

        Extracts schemas to a temporary directory, then atomically replaces
        the live providers/ and resources/ directories.

        Args:
            cache_dir: The cache directory root
            force: Whether the update was forced
        Returns:
            int: exit code (0=success, 2=failure)
        """
        # Re-check version under lock in case another process just updated.
        # url_has_newer_version() makes a network request; URLError subclasses
        # OSError, so handle it here rather than letting it propagate to the
        # caller's lock-acquisition handler. This keeps the invariant that
        # _update_locked never raises — it always returns an exit code.
        try:
            if not force and not url_has_newer_version(_ENHANCED_SCHEMAS_URL):
                LOGGER.info("Schemas were updated by another process")
                return 0
        except OSError as e:
            LOGGER.error("Failed to check schema version: %s", e)
            return 2

        try:
            pending_metadata = get_url_metadata(_ENHANCED_SCHEMAS_URL)
            filehandle = get_url_retrieve(_ENHANCED_SCHEMAS_URL)
        except Exception as e:
            LOGGER.error(
                "Failed to download enhanced schemas; metadata was not updated: %s",
                e,
            )
            return 2

        providers_dir = cache_dir / "providers"
        resources_dir = cache_dir / "resources"

        # Extract to a temporary directory, then atomically swap
        try:
            with tempfile.TemporaryDirectory(dir=cache_dir) as tmpdir:
                tmp_path = Path(tmpdir)
                tmp_providers = tmp_path / "providers"
                tmp_resources = tmp_path / "resources"
                tmp_providers.mkdir()
                tmp_resources.mkdir()

                with zipfile.ZipFile(filehandle, "r") as zip_ref:
                    for name in zip_ref.namelist():
                        if not name.endswith(".json"):
                            continue
                        if name.startswith("providers/"):
                            dest = tmp_providers / Path(name).name
                            with zip_ref.open(name) as src, open(dest, "wb") as dst:
                                dst.write(src.read())
                        elif name.startswith("resources/"):
                            dest = tmp_resources / Path(name).name
                            with zip_ref.open(name) as src, open(dest, "wb") as dst:
                                dst.write(src.read())

                # Atomic replacement: remove old, rename new. On POSIX, rename()
                # is atomic when src and dst share a filesystem, which is
                # guaranteed here by extracting under the same cache_dir.
                self._atomic_replace_dir(tmp_providers, providers_dir)
                self._atomic_replace_dir(tmp_resources, resources_dir)
        except (OSError, zipfile.BadZipFile) as e:
            LOGGER.error(
                "Failed to extract and install schemas; metadata was not updated: %s",
                e,
            )
            return 2

        if pending_metadata:
            try:
                save_metadata(*pending_metadata)
                LOGGER.debug("Schema cache metadata updated after installation")
            except OSError as e:
                LOGGER.error(
                    "Schemas installed but failed to update schema cache metadata: %s",
                    e,
                )
                return 2
        else:
            LOGGER.debug("No schema ETag returned; cache metadata was not updated")

        try:
            version_content = get_url_content(_VERSION_URL)
            # Validate structure before persisting: it must be a JSON
            # object with a parseable ISO-8601 ``schema_date``. Writing
            # unvalidated content lets a malformed or attacker-shaped
            # payload sit on disk and later confuse _resolve_schema_dirs.
            parsed = json.loads(version_content)
            if not isinstance(parsed, dict):
                raise ValueError("version.json is not a JSON object")
            schema_date = parsed.get("schema_date")
            if not isinstance(schema_date, str) or (
                ProviderSchemaManager._parse_schema_date(schema_date) is None
            ):
                raise ValueError(
                    "version.json does not contain a parseable schema_date"
                )
            with open(cache_dir / "version.json", "w", encoding="utf-8") as vf:
                vf.write(version_content)
        except Exception as e:
            LOGGER.debug("Could not download or validate version.json: %s", e)

        self._providers_dir = providers_dir
        self._resources_dir = resources_dir
        LOGGER.info("Schemas updated successfully")
        self.reset()
        return 0

    @staticmethod
    def _atomic_replace_dir(src: Path, dst: Path) -> None:
        """Atomically replace dst directory with src.

        Renames any existing dst to a backup, renames src to dst,
        then removes the backup. If rename fails (cross-device),
        falls back to shutil.move.

        Args:
            src: Source directory (will be moved)
            dst: Destination directory (will be replaced)
        """
        backup = dst.with_suffix(".bak")

        # Remove any stale backup from a previous failed update
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)

        # Move existing dst out of the way
        if dst.exists():
            try:
                dst.rename(backup)
            except OSError:
                # Cross-device or other issue; use shutil
                shutil.move(str(dst), str(backup))

        # Move new dir into place
        try:
            src.rename(dst)
        except OSError:
            shutil.move(str(src), str(dst))

        # Clean up backup
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)

    def patch(self, patch: SchemaPatch, region: str) -> None:
        """Patch the schemas as needed

        Args:
            patch: The patches to be applied to the schemas
        Returns:
            None: Returns when completed
        """

        resource_types = []
        all_resource_types = self.get_resource_types(region)[:]
        # Remove unsupported resource using includes
        if patch.included_resource_types:
            for include in patch.included_resource_types:
                regex = re.compile(include.replace("*", "(.*)") + "$")
                matches = [
                    string for string in all_resource_types if re.match(regex, string)
                ]

                resource_types.extend(matches)
        else:
            resource_types = all_resource_types[:]

        # Remove unsupported resources using the excludes
        for exclude in patch.excluded_resource_types:
            regex = re.compile(exclude.replace("*", "(.*)") + "$")
            matches = [string for string in resource_types if re.match(regex, string)]
            for match in matches:
                resource_types.remove(match)

        # Remove unsupported resources
        removed_types = list(set(all_resource_types) - set(resource_types))
        if removed_types:
            for removed_type in removed_types:
                self._removed_types.append(removed_type)
            self.get_resource_schema.cache_clear()
            self.get_resource_types.cache_clear()

        for resource_type, patches in patch.patches.items():
            try:
                schema = self.get_resource_schema(
                    resource_type=resource_type, region=region
                )
            except ResourceNotFoundError:
                # Resource type doesn't exist in this region
                continue
            try:
                schema.patch(patches=patches)
            except Exception as e:
                print(f"Error applying patch {patches} for {resource_type}: {e}")
                sys.exit(1)

    @lru_cache(maxsize=None)
    def get_type_getatts(self, resource_type: str, region: str) -> AttributeDict:
        """Get the GetAtts for a type in a region

        Args:
            resource_type: The type of the resource. Example: AWS::S3::Bucket
            region: The region to load the resource type from
        Returns:
            Dict(str, Dict): Returns a Dict where the keys are the attributes and the
                value is the CloudFormation schema description of the attribute
        """
        schema = self.get_resource_schema(region=region, resource_type=resource_type)
        return schema.get_atts

    @lru_cache(maxsize=None)
    def get_type_ref(self, resource_type: str, region: str) -> dict[str, Any]:
        """Get the Ref information for a type in a region

        Args:
            resource_type: The type of the resource. Example: AWS::S3::Bucket
            region: The region to load the resource type from
        Returns:
            dict(str, Any): Returns a Dict where the keys are the attributes and the
                value is the CloudFormation schema description of the attribute
        """
        schema = self.get_resource_schema(region=region, resource_type=resource_type)
        return schema.ref


PROVIDER_SCHEMA_MANAGER: ProviderSchemaManager = ProviderSchemaManager()
