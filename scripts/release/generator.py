#!/usr/bin/env python
"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import logging
import os
import re
import zipfile
from collections import deque
from pathlib import Path

import _translator

from cfnlint.helpers import REGIONS, ToPy, format_json_string, load_plugins
from cfnlint.schema import PROVIDER_SCHEMA_MANAGER

# Resource type names come from the downloaded providers/<region>.json whose
# keys are not inherently trustworthy. Restrict them to the CloudFormation
# ``A::B::C`` grammar (plus the known ``Module`` special case) before using
# them to build output file paths, to prevent path traversal via crafted
# resource-type keys (CWE-22).
_RESOURCE_TYPE_RE = re.compile(r"^[A-Za-z0-9]+::[A-Za-z0-9]+::[A-Za-z0-9]+$")
_SPECIAL_RESOURCE_TYPES = frozenset({"Module"})


def _is_safe_resource_type(resource_type: str) -> bool:
    """Return True if ``resource_type`` is safe to interpolate into a path."""
    if resource_type in _SPECIAL_RESOURCE_TYPES:
        return True
    return bool(_RESOURCE_TYPE_RE.match(resource_type))


def _safe_output_path(base_dir: Path, filename: str) -> Path:
    """Join ``filename`` under ``base_dir`` and assert containment.

    Uses ``os.path.basename`` to strip any directory components and then
    verifies via ``Path.resolve().is_relative_to()`` that the resulting path
    does not escape ``base_dir`` (defence in depth against path traversal).
    """
    safe_name = os.path.basename(filename)
    candidate = (base_dir / safe_name).resolve()
    if not candidate.is_relative_to(base_dir.resolve()):
        raise ValueError(
            f"Refusing to write outside {base_dir!s}: {filename!r}"
        )
    return candidate

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def _get_schema_path(schema, path):
    s = schema.schema
    schema_path = deque([])
    while path:
        key = path.popleft()
        if key == "*":
            schema_path.append("items")
            s = s["items"]
        else:
            s = s["properties"][key]
            schema_path.extend(["properties", key])

        pointer = s.get("$ref")
        if pointer:
            _, s = schema.resolver.resolve(pointer)
            schema_path = deque(pointer.split("/")[1:])

    return schema_path


def _build_patch(path, patch):
    if not path:
        path_str = "/allOf"
    else:
        path_str = f"/{'/'.join(path)}/allOf"

    return (
        [
            {
                "op": "add",
                "path": path_str,
                "value": [],
            }
        ],
        [
            {
                "op": "add",
                "path": f"{path_str}/-",
                "value": patch,
            }
        ],
    )


schemas = {}

##########################
#
# Build the definitive list of all resource types across all regions
#
###########################

for region in ["us-east-1"] + list((set(REGIONS) - set(["us-east-1"]))):
    for resource_type in PROVIDER_SCHEMA_MANAGER.get_resource_types(region):
        if resource_type in ["AWS::CDK::Metadata", "Module"]:
            continue
        if resource_type not in schemas:
            schemas[resource_type] = region


##########################
#
# Merge in rule schemas into the resource schemas
#
###########################

rules_folder = Path("src") / "cfnlint" / "rules"

rules = load_plugins(
    rules_folder,
    name="CfnLintJsonSchema",
    modules=(
        "cfnlint.rules.jsonschema.CfnLintJsonSchema",
        "cfnlint.rules.jsonschema.CfnLintJsonSchema.CfnLintJsonSchema",
    ),
)

for rule in rules:
    if rule.__class__.__base__.__name__ == "CfnLintJsonSchemaRegional":
        continue
    if not rule.id or rule.schema == {}:
        continue

    for keyword in rule.keywords:
        if not keyword.startswith("Resources/"):
            continue
        path = deque(keyword.split("/"))

        if len(path) < 3:
            continue

        path.popleft()
        resource_type = path.popleft()
        resource_properties = path.popleft()
        if resource_type not in schemas and resource_properties != "Properties":
            continue

        schema_path = _get_schema_path(
            PROVIDER_SCHEMA_MANAGER.get_resource_schema(
                schemas[resource_type], resource_type
            ),
            path,
        )
        all_of_patch, schema_patch = _build_patch(schema_path, rule.schema)

        PROVIDER_SCHEMA_MANAGER._schemas[schemas[resource_type]][resource_type].patch(
            patches=all_of_patch
        )
        PROVIDER_SCHEMA_MANAGER._schemas[schemas[resource_type]][resource_type].patch(
            patches=schema_patch
        )

        logger.info(f"Patch {rule.id} for {resource_type} in {schemas[resource_type]}")


build_dir = Path("build")
schemas_dir = build_dir / "schemas"
schemas_cfnlint_dir = schemas_dir / "cfnlint"
schemas_cfnlint_dir.mkdir(parents=True, exist_ok=True)

schemas_draft7_dir = schemas_dir / "draft7"
schemas_draft7_dir.mkdir(parents=True, exist_ok=True)

for resource_type, region in schemas.items():
    if not _is_safe_resource_type(resource_type):
        logger.warning(
            "Skipping untrusted resource type name %r for region %s",
            resource_type,
            region,
        )
        continue

    rt_py = ToPy(resource_type)

    cfnlint_out = _safe_output_path(schemas_cfnlint_dir, f"{rt_py.py}.json")
    with open(cfnlint_out, "w") as f:
        f.write(
            format_json_string(
                PROVIDER_SCHEMA_MANAGER.get_resource_schema(
                    region, resource_type
                ).schema
            )
        )

    _translator.translator(resource_type, region)

    draft7_out = _safe_output_path(schemas_draft7_dir, f"{rt_py.py}.json")
    with open(draft7_out, "w") as f:
        f.write(
            format_json_string(
                PROVIDER_SCHEMA_MANAGER.get_resource_schema(
                    region, resource_type
                ).schema
            )
        )

logger.info("Create schema package")
with zipfile.ZipFile(
    build_dir / "schemas-cfnlint.zip", "w", zipfile.ZIP_DEFLATED
) as zf:
    for file_path in schemas_cfnlint_dir.rglob("*"):
        if file_path.is_file():
            zf.write(file_path, f"schemas/{file_path.relative_to(schemas_cfnlint_dir)}")

with zipfile.ZipFile(build_dir / "schemas-draft7.zip", "w", zipfile.ZIP_DEFLATED) as zf:
    for file_path in schemas_draft7_dir.rglob("*"):
        if file_path.is_file():
            zf.write(file_path, f"schemas/{file_path.relative_to(schemas_draft7_dir)}")
