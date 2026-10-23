"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from cfnlint.helpers import is_function

# Globals section key -> resource type
_GLOBALS_TYPE_MAP: dict[str, str] = {
    "Function": "AWS::Serverless::Function",
    "Api": "AWS::Serverless::Api",
    "HttpApi": "AWS::Serverless::HttpApi",
    "SimpleTable": "AWS::Serverless::SimpleTable",
    "StateMachine": "AWS::Serverless::StateMachine",
    "LayerVersion": "AWS::Serverless::LayerVersion",
    "CapacityProvider": "AWS::Serverless::CapacityProvider",
    "WebSocketApi": "AWS::Serverless::WebSocketApi",
}

# Resource-management budgets that bound how much the SAM Globals merge may
# expand the template.  _MAX_MERGED_NODES mirrors the decoder's existing
# _MAX_EXPANDED_NODES (250_000) and caps the total number of nodes produced
# by the merge: a Globals subtree of g nodes merged into r matching
# resources costs roughly g * r nodes, so we reject the merge when that
# product crosses the budget.  _MAX_MERGE_DEPTH prevents unbounded
# recursion through nested dicts.  _MAX_MERGED_LIST_LEN caps the single
# list concatenation that the merge performs.
_MAX_MERGED_NODES = 250_000
_MAX_MERGE_DEPTH = 100
_MAX_MERGED_LIST_LEN = 10_000


class SAMGlobalsMergeError(Exception):
    """Raised when the SAM Globals merge would exceed a resource budget."""


def _is_intrinsic(value: Any) -> bool:
    k, _ = is_function(value)
    return k is not None


def _count_nodes(value: Any, limit: int) -> int:
    """Return the (bounded) node count of ``value``.

    Walks dicts and lists, counting one node per container and one per
    scalar leaf.  Returns at most ``limit + 1`` so callers can detect
    the exceeded case without walking the full input.
    """
    total = 0
    stack: list[Any] = [value]
    while stack:
        node = stack.pop()
        total += 1
        if total > limit:
            return total
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return total


def _merge(global_value: Any, local_value: Any, depth: int = 0) -> Any:
    """Merge a global value with a local value.

    Rules (matching SAM translator behavior):
    - Primitives/intrinsics: local wins
    - Dicts: recursive merge, local keys override
    - Lists: concatenate global + local (capped)
    - Type mismatch: local wins

    ``depth`` guards against unbounded recursion through nested dicts
    and is bounded by ``_MAX_MERGE_DEPTH``.
    """
    if depth >= _MAX_MERGE_DEPTH:
        raise SAMGlobalsMergeError(
            f"SAM Globals merge exceeded maximum depth of {_MAX_MERGE_DEPTH}"
        )

    if isinstance(global_value, dict) and isinstance(local_value, dict):
        if _is_intrinsic(global_value) or _is_intrinsic(local_value):
            return local_value
        result = global_value.copy()
        for k, v in local_value.items():
            result[k] = (
                _merge(result[k], v, depth + 1) if k in result else v
            )
        return result

    if isinstance(global_value, list) and isinstance(local_value, list):
        if len(global_value) + len(local_value) > _MAX_MERGED_LIST_LEN:
            raise SAMGlobalsMergeError(
                "SAM Globals merge would concatenate a list longer than "
                f"{_MAX_MERGED_LIST_LEN} elements"
            )
        return global_value + local_value

    return local_value


def merge_globals(template: dict[str, Any]) -> dict[str, Any]:
    """Merge Globals properties into SAM resources.

    Modifies the template in place and returns it.
    Does nothing if there is no Globals section.

    Raises :class:`SAMGlobalsMergeError` when the merge would exceed one of
    the configured resource budgets (total node count after expansion,
    recursion depth, or single-list concatenation length).  Callers are
    expected to translate that into a lint ``TransformError`` match.
    """
    globals_section = template.get("Globals")
    if not isinstance(globals_section, dict):
        return template

    resources = template.get("Resources")
    if not isinstance(resources, dict):
        return template

    # Build a map of resource_type -> global properties
    globals_by_type: dict[str, dict[str, Any]] = {}
    for section_name, props in globals_section.items():
        resource_type = _GLOBALS_TYPE_MAP.get(section_name)
        if resource_type and isinstance(props, dict):
            globals_by_type[resource_type] = props

    if not globals_by_type:
        return template

    # Count how many resources each Globals subtree would be merged into so
    # we can reject the (globals_size x resource_count) product before
    # paying the deepcopy cost.
    matches_by_type: dict[str, int] = {t: 0 for t in globals_by_type}
    for resource in resources.values():
        if not isinstance(resource, dict):
            continue
        resource_type = resource.get("Type")
        if resource_type not in matches_by_type:
            continue
        if resource.get("IgnoreGlobals") == "*":
            continue
        matches_by_type[resource_type] += 1

    # Compute the (bounded) node size of each Globals subtree once and the
    # projected total node count after the merge.  Short-circuit as soon
    # as the running total crosses the budget so a large Globals blob
    # cannot force a full walk just to measure it.
    projected_nodes = 0
    for resource_type, props in globals_by_type.items():
        n = _count_nodes(props, _MAX_MERGED_NODES)
        projected_nodes += n * max(matches_by_type[resource_type], 1)
        if projected_nodes > _MAX_MERGED_NODES:
            raise SAMGlobalsMergeError(
                "SAM Globals merge would expand to more than "
                f"{_MAX_MERGED_NODES} nodes "
                "(Globals section size times matching resource count); "
                "refusing to expand to bound resource usage"
            )

    # Merge into each matching resource
    for resource in resources.values():
        if not isinstance(resource, dict):
            continue
        resource_type = resource.get("Type")
        if resource_type not in globals_by_type:
            continue

        # Support IgnoreGlobals attribute
        ignore = resource.get("IgnoreGlobals")
        if ignore == "*":
            continue

        # Only deepcopy when the global subtree is about to be mutated
        # (IgnoreGlobals pops keys from it).  ``_merge`` itself does not
        # mutate ``global_value``: it shallow-copies dicts and returns a
        # fresh list for list concatenation, so sharing immutable
        # subtrees across resources is safe.
        source = globals_by_type[resource_type]
        if isinstance(ignore, list):
            global_props = deepcopy(source)
            for key in ignore:
                global_props.pop(key, None)
        else:
            global_props = source

        local_props = resource.get("Properties")
        if not isinstance(local_props, dict):
            local_props = {}

        resource["Properties"] = _merge(global_props, local_props)

    return template
