"""
Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import zipfile
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

# Release pinning + integrity verification configuration.
#
# The schema corpus is published as a GitHub release asset. Using the mutable
# ``latest`` tag means any party with write access to the publishing repo can
# silently substitute the artifact that drives every cfn-lint validation.
# Operators pin a specific immutable tag (and an expected SHA-256 of the zip)
# by shipping ``src/cfnlint/data/schemas/release.json``:
#
#     {"tag": "v2024.10.01", "sha256": "<64-hex>"}
#
# When ``sha256`` is set, ``_update_locked`` recomputes the digest of the
# downloaded zip and aborts the install on any mismatch. When ``tag`` is set,
# the download URL is built from that tag instead of ``latest``.
# Both can also be overridden at runtime via environment variables, which is
# useful in CI/CD (e.g. the release workflow pins to the exact tag it tests):
#
#   CFN_LINT_SCHEMAS_RELEASE_TAG   release tag to download from
#   CFN_LINT_SCHEMAS_SHA256        expected SHA-256 of schemas-cfn-lint.zip
_DEFAULT_SCHEMAS_RELEASE_TAG = "latest"
_SCHEMAS_RELEASE_FILE = (
    Path(os.path.dirname(__file__)) / ".." / "data" / "schemas" / "release.json"
)

# Decompression bomb bounds. These generously exceed the real corpus
# (hundreds of small JSON files, each a few KB-few hundred KB) while still
# killing a hostile asset that tries to exhaust memory or disk.
_MAX_MEMBER_BYTES = 32 * 1024 * 1024  # 32 MiB per JSON member
_MAX_TOTAL_BYTES = 512 * 1024 * 1024  # 512 MiB across all members

# Opt-in gate for the implicit network install that previously fired on every
# lint when the cache was empty. See ``_load_provider_module``. Operators who
# accept the network+integrity risk set this to a truthy value; everyone else
# must run ``cfn-lint --update-specs`` explicitly.
_AUTO_UPDATE_ENV_VAR = "CFN_LINT_SCHEMAS_AUTO_UPDATE"


def _load_release_pin() -> dict[str, str]:
    """Load the packaged release pin (tag + expected sha256) if present.

    Environment variables take precedence over the packaged file so CI jobs
    (and the cfn-lint release workflow in cd-pypi.yaml) can pin a specific
    tag/digest for the duration of the build without editing the tree.
    Returns an empty dict when nothing is configured.
    """
    pin: dict[str, str] = {}
    try:
        if _SCHEMAS_RELEASE_FILE.exists():
            with open(_SCHEMAS_RELEASE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for key in ("tag", "sha256"):
                    value = data.get(key)
                    if isinstance(value, str) and value:
                        pin[key] = value
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning(
            "Could not read packaged schema release pin %s: %s",
            _SCHEMAS_RELEASE_FILE,
            exc,
        )
    env_tag = os.environ.get("CFN_LINT_SCHEMAS_RELEASE_TAG")
    if env_tag:
        pin["tag"] = env_tag
    env_sha = os.environ.get("CFN_LINT_SCHEMAS_SHA256")
    if env_sha:
        pin["sha256"] = env_sha.lower()
    elif "sha256" in pin:
        pin["sha256"] = pin["sha256"].lower()
    return pin


def _enhanced_schemas_urls() -> tuple[str, str]:
    """Return (schemas_zip_url, version_json_url) for the pinned release."""
    tag = _load_release_pin().get("tag") or _DEFAULT_SCHEMAS_RELEASE_TAG
    base = (
        "https://github.com/aws-cloudformation/"
        f"resource-provider-enhanced-schemas/releases/download/{tag}"
    )
    return f"{base}/schemas-cfn-lint.zip", f"{base}/version.json"


_ENHANCED_SCHEMAS_URL, _VERSION_URL = _enhanced_schemas_urls()


def _sha256_of_file(path: str) -> str:
    """Streaming SHA-256 of a local file as lowercase hex."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_zip_member(zip_ref: "zipfile.ZipFile", info: "zipfile.ZipInfo",
                    max_bytes: int) -> bytes:
    """Read a single zip member, failing fast on oversized decompression.

    Streams the member in 64 KiB chunks and aborts as soon as the
    decompressed length exceeds ``max_bytes`` so a hostile ``schemas-cfn-
    lint.zip`` cannot force cfn-lint to allocate unbounded memory or disk
    (a zip-bomb availability hit on CI). The chunked read also replaces the
    previous unbounded ``src.read()``.
    """
    buf = bytearray()
    with zip_ref.open(info, "r") as src:
        while True:
            chunk = src.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > max_bytes:
                raise ValueError(
                    f"schema member {info.filename!r} exceeds the "
                    f"{max_bytes}-byte per-member limit"
                )
    return bytes(buf)

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
        """Read schema_date from a version.json file."""
        version_file = directory / "version.json"
        try:
            with open(version_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                result: str = data.get("schema_date", "")
                return result
        except (FileNotFoundError, json.JSONDecodeError):
            return ""

    @staticmethod
    def _resolve_schema_dirs() -> tuple[Path, Path]:
        """Determine which schema directory to use.

        Precedence:
        1. If both bundled and cache exist, use whichever has a newer schema_date
        2. If only bundled exists, use bundled
        3. If only cache exists, use cache
        4. If neither exists, use cache (auto-download will populate it)
        """
        _pkg_data = Path(os.path.dirname(__file__), "..", "data", "schemas")
        _pkg_providers = _pkg_data / "providers"
        _cache = Path(get_cache_dir())
        _cache_providers = _cache / "providers"

        bundled_exists = _pkg_providers.exists() and any(_pkg_providers.glob("*.json"))
        cache_exists = _cache_providers.exists() and any(
            _cache_providers.glob("*.json")
        )

        if bundled_exists and cache_exists:
            bundled_date = ProviderSchemaManager._read_schema_date(_pkg_data)
            cache_date = ProviderSchemaManager._read_schema_date(_cache)
            if cache_date > bundled_date:
                return _cache / "providers", _cache / "resources"
            return _pkg_providers, _pkg_data / "resources"

        if bundled_exists:
            return _pkg_providers, _pkg_data / "resources"

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
                # Implicit network install during an ordinary lint is
                # opt-in: downloading schemas on first use is an integrity
                # risk (CWE-1214) because the artifact drives all template
                # validation. Operators who accept that risk set
                # CFN_LINT_SCHEMAS_AUTO_UPDATE=1; everyone else must run
                # ``cfn-lint --update-specs`` explicitly.
                if os.environ.get(_AUTO_UPDATE_ENV_VAR, "").strip().lower() in (
                    "1",
                    "true",
                    "yes",
                    "on",
                ):
                    self.update(force=False)
                else:
                    LOGGER.warning(
                        "CloudFormation provider schemas are not installed "
                        "(looked under %s). Run `cfn-lint --update-specs` to "
                        "install them, or set %s=1 to allow implicit "
                        "downloads during linting.",
                        self._providers_dir,
                        _AUTO_UPDATE_ENV_VAR,
                    )
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

        # Integrity check: compare the actual sha256 to the pin before we
        # install a single byte over the live cache. If no pin is configured
        # we at least emit the digest at WARNING so operators have the value
        # they need to pin on the next run.
        pin = _load_release_pin()
        try:
            actual_sha256 = _sha256_of_file(filehandle)
        except OSError as e:
            LOGGER.error(
                "Failed to read downloaded schemas for integrity check: %s", e
            )
            return 2
        expected_sha256 = pin.get("sha256")
        if expected_sha256:
            if actual_sha256 != expected_sha256:
                LOGGER.error(
                    "Schema archive integrity check failed: expected sha256 %s, "
                    "got %s; refusing to install. Verify the pinned release and "
                    "update src/cfnlint/data/schemas/release.json (or "
                    "CFN_LINT_SCHEMAS_SHA256) if the pin is intentionally rolling.",
                    expected_sha256,
                    actual_sha256,
                )
                return 2
            LOGGER.debug(
                "Schema archive sha256 verified: %s", actual_sha256
            )
        else:
            LOGGER.warning(
                "Schema archive sha256 is %s (no pin configured; set "
                "CFN_LINT_SCHEMAS_SHA256 or ship src/cfnlint/data/schemas/"
                "release.json to enforce integrity).",
                actual_sha256,
            )

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

                total_bytes = 0
                with zipfile.ZipFile(filehandle, "r") as zip_ref:
                    for info in zip_ref.infolist():
                        name = info.filename
                        if not name.endswith(".json"):
                            continue
                        if name.startswith("providers/"):
                            dest = tmp_providers / Path(name).name
                        elif name.startswith("resources/"):
                            dest = tmp_resources / Path(name).name
                        else:
                            continue

                        payload = _read_zip_member(
                            zip_ref, info, _MAX_MEMBER_BYTES
                        )
                        total_bytes += len(payload)
                        if total_bytes > _MAX_TOTAL_BYTES:
                            raise ValueError(
                                "schema archive exceeds the "
                                f"{_MAX_TOTAL_BYTES}-byte total decompressed "
                                "size limit"
                            )

                        # Validate the payload is a JSON object. This blocks a
                        # hostile ``.json`` member that contains binary garbage
                        # or an unexpected type (list/string/number) from ever
                        # reaching the live cache where ``json.load`` would
                        # later blow up or feed the linter nonsense data.
                        try:
                            parsed = json.loads(payload.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError) as e:
                            raise ValueError(
                                f"schema member {name!r} is not valid UTF-8 JSON"
                                f": {e}"
                            ) from e
                        if not isinstance(parsed, dict):
                            raise ValueError(
                                f"schema member {name!r} is not a JSON object"
                            )
                        with open(dest, "wb") as dst:
                            dst.write(payload)

                # Atomic replacement: remove old, rename new. On POSIX, rename()
                # is atomic when src and dst share a filesystem, which is
                # guaranteed here by extracting under the same cache_dir.
                self._atomic_replace_dir(tmp_providers, providers_dir)
                self._atomic_replace_dir(tmp_resources, resources_dir)
        except (OSError, zipfile.BadZipFile, ValueError) as e:
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
            with open(cache_dir / "version.json", "w", encoding="utf-8") as vf:
                vf.write(version_content)
        except Exception:
            LOGGER.debug("Could not download version.json")

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
