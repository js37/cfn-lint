"""
Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import string
from copy import deepcopy
from typing import Any, Iterator, Mapping, MutableMapping, Tuple

import regex as re

from cfnlint.conditions._utils import get_hash
from cfnlint.decode.node import str_node
from cfnlint.helpers import FUNCTION_FOR_EACH, REGEX_SUB_PARAMETERS
from cfnlint.template.transforms._types import TransformResult

LOGGER = logging.getLogger("cfnlint")

# initializing size of string
_N = 7

_SCALAR_TYPES = (str, int, float, bool)

_ACCOUNT_ID = None

# Maximum depth of nested Fn::FindInMap expressions.  Without this cap a
# chain of nested Fn::FindInMap expressions resolves in O((M*K)**depth)
# because each level scans the Mappings section while repeatedly
# re-resolving its child expression.  A small, generous bound keeps
# well-formed templates working while making the attacker-controlled
# recursion refuse to even construct beyond a safe depth.
_MAX_FINDINMAP_DEPTH = 8

# Overall step budget for a single transform.  Even with memoization and
# shallow copies in place, a template could still try to exhaust CPU by
# producing a very large number of resolutions through other means.  The
# budget is intentionally large so legitimate templates are unaffected,
# but it guarantees the transform cannot run unbounded on a hostile
# input.
_TRANSFORM_STEP_BUDGET = 1_000_000

# Sentinel used by the memoization cache to distinguish "no cached
# result" from "cached result is None".
_CACHE_MISS = object()


class _ResolveError(Exception):
    def __init__(self, message: str, key: Any) -> None:
        super().__init__(message)
        self.key = key


class _ValueError(Exception):
    def __init__(self, message: str, key: Any) -> None:
        super().__init__(message)
        self.key = key


class _TypeError(Exception):
    def __init__(self, message: str, key: Any) -> None:
        super().__init__(message)
        self.key = key


def language_extension(cfn: Any) -> TransformResult:
    transform = _Transform()
    try:
        return transform.transform(cfn)
    except (_ValueError, _TypeError, _ResolveError) as e:
        LOGGER.debug(e, exc_info=True)
        # pylint: disable=import-outside-toplevel
        from cfnlint.match import Match  # pylint: disable=cyclic-import
        from cfnlint.rules.errors import TransformError  # pylint: disable=cyclic-import

        message = "Error transforming template: {0}"
        if hasattr(e.key, "start_mark"):
            sm_line = e.key.start_mark.line + 1
            sm_column = e.key.start_mark.column + 1
        else:
            sm_line = 1
            sm_column = 1
        if hasattr(e.key, "end_mark"):
            em_line = e.key.end_mark.line + 1
            em_column = e.key.end_mark.column + 1
        else:
            em_line = 1
            em_column = 1

        return [
            Match.create(
                linenumber=sm_line,
                columnnumber=sm_column,
                linenumberend=em_line,
                columnnumberend=em_column,
                filename=cfn.filename,
                rule=TransformError(),
                message=message.format(str(e)),
            )
        ], None
    except Exception as e:  # pylint: disable=broad-exception-caught
        LOGGER.debug(e, exc_info=True)
        # pylint: disable=import-outside-toplevel
        from cfnlint.match import Match  # pylint: disable=cyclic-import
        from cfnlint.rules.errors import TransformError  # pylint: disable=cyclic-import

        message = "Error transforming template: {0}"
        return [
            Match.create(
                filename=cfn.filename,
                rule=TransformError(),
                message=message.format(str(e)),
            )
        ], None


class _Transform:
    def __init__(self) -> None:
        self._collections: MutableMapping[str, str] = {}
        self._steps_remaining: int = _TRANSFORM_STEP_BUDGET

    def _tick(self, key: Any) -> None:
        """Charge one step against the overall transform budget.

        Raised as ``_ValueError`` so ``language_extension`` surfaces it as
        a clean ``TransformError`` match (see the ``except`` block in
        :func:`language_extension`).
        """
        self._steps_remaining -= 1
        if self._steps_remaining < 0:
            raise _ValueError(
                "Transform exceeded resource budget while expanding template",
                key,
            )

    def transform(self, cfn: Any) -> TransformResult:
        """Transform the template"""
        return [], self._walk(cfn.template, {}, cfn)

    # pylint: disable=too-many-return-statements
    def _walk(self, item: Any, params: MutableMapping[str, Any], cfn: Any):
        obj = deepcopy(item)
        if isinstance(obj, dict):
            # adjust keys if needed
            if params:
                for k, v in item.items():
                    _, new_k = self._replace_string_params(k, params)
                    if new_k != k:
                        del obj[k]
                        obj[new_k] = v

            for k, v in deepcopy(obj).items():
                self._tick(k)
                # see if key matches Fn::ForEach
                if re.match(FUNCTION_FOR_EACH, k):
                    # only translate the foreach if its valid
                    foreach = _ForEach(k, v, self._collections)
                    # get the values will flatten the foreach
                    for collection_value in foreach.items(cfn, params):
                        flattened = self._walk(
                            v[2], {**params, **{v[0]: collection_value}}, cfn
                        )
                        for f_k, f_v in flattened.items():
                            if f_k not in obj:
                                obj[f_k] = f_v
                            else:
                                raise _ValueError(
                                    f"Duplicate {f_k} while doing transformation",
                                    f_k,
                                )
                    del obj[k]
                elif k == "Fn::ToJsonString":
                    # extra special handing for this as {} could be a valid value
                    return obj
                elif k == "Fn::GetAtt":
                    if isinstance(v, (list, str)):
                        obj[k] = self._walk(v, params, cfn)
                elif k == "Fn::Sub":
                    if isinstance(v, str):
                        only_string, obj[k] = self._replace_string_params(v, params)
                        if only_string:
                            return obj[k]
                    if isinstance(v, list):
                        only_string, obj[k][0] = self._replace_string_params(
                            v[0],
                            params,
                        )
                        if only_string:
                            return obj[k][0]
                        if len(v) == 2:
                            obj[k][1] = self._walk(v[1], params, cfn)
                elif k == "Fn::FindInMap":
                    try:
                        mapping = _ForEachValueFnFindInMap(get_hash(v), v)
                        map_value = mapping.value(cfn, params, True, False)
                        # if we can resolve it we will return it
                        if isinstance(map_value, tuple([list]) + _SCALAR_TYPES):
                            # Return an independent copy of the resolved value.
                            # ``mapping.value`` hands back the object stored in
                            # the ``Mappings`` section, so returning it directly
                            # makes every location that resolves to the same
                            # mapping entry share one object. That shared
                            # identity looks like a YAML alias to W1101 (false
                            # positive, issue #4697) and lets a later mutation of
                            # one location bleed into the mapping definition.
                            return deepcopy(map_value)
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        # We couldn't resolve the FindInMap so we are going to
                        # leave it as it is
                        LOGGER.debug("Transform and Fn::FindInMap error: %s", {str(e)})
                    for i, el in enumerate(v):
                        v[i] = self._walk(el, params, cfn)
                    obj[k] = v
                elif k == "Ref":
                    if isinstance(v, str):
                        if v in params:
                            # Copy so two Refs to the same parameter do not
                            # share one object (see the Fn::FindInMap note
                            # above / issue #4697).
                            return deepcopy(params[v])
                    elif isinstance(v, dict):
                        r = self._walk(v, params, cfn)
                        if isinstance(r, str):
                            if r in params:
                                return deepcopy(params[r])
                        obj[k] = r
                elif k == "Fn::If":
                    if isinstance(v, list) and len(v) == 3:
                        # CloudFormation does not resolve the condition name
                        # (index 0) inside Fn::ForEach, so we leave it as-is
                        # and only walk the true/false branches.
                        obj[k][1] = self._walk(v[1], params, cfn)
                        obj[k][2] = self._walk(v[2], params, cfn)
                else:
                    sub_value = self._walk(v, params, cfn)
                    # a sub object may be none or we have returned
                    # an empty object.  We don't want to remove empty
                    # strings "" or 0 (zeros)
                    # Remove `or sub_value == {}` for issue #2896
                    if sub_value is None:
                        del obj[k]
                    else:
                        obj[k] = sub_value
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                obj[i] = self._walk(v, params, cfn)
        return obj

    def _replace_string_params(
        self,
        s: str,
        params: Mapping[str, Any],
    ) -> Tuple[bool, str]:
        _ampersand_pattern = re.compile(r"&{\s*[^!\s].*?\s*}")

        def _has_variables(value: str) -> bool:
            return bool(
                REGEX_SUB_PARAMETERS.search(value) or _ampersand_pattern.search(value)
            )

        if not _has_variables(s):
            return (True, s)

        new_s = deepcopy(s)
        for k, v in params.items():
            if isinstance(v, dict):
                v = (
                    hashlib.md5(json.dumps(v).encode("utf-8"), usedforsecurity=False)
                    .digest()
                    .hex()[0:4]
                )
            new_s = re.sub(rf"\$\{{{k}\}}", v, new_s)
            new_s = re.sub(rf"\&\{{{k}\}}", re.sub("[^0-9a-zA-Z]+", "", v), new_s)

        if isinstance(s, str_node):
            new_s = str_node(new_s, s.start_mark, s.end_mark)

        return (not _has_variables(new_s), new_s)


class _ForEachValue:
    def __init__(self, _hash: str, value: Any = None) -> None:
        if value:
            self._value = value

        self._hash = _hash
        # Per-instance memoization table for ``value()``.  Keyed by
        # ``(id(cfn), params_hash, only_params)`` so repeated calls with
        # the same inputs do not re-resolve the whole sub-expression
        # tree.  See _ForEachValueFnFindInMap.value for the exponential
        # scan loop this protects.
        self._value_cache: dict[tuple, Any] = {}

    @staticmethod
    def create(obj: Any, _depth: int = 0) -> _ForEachValue:
        if _depth > _MAX_FINDINMAP_DEPTH:
            # Refuse to build a sub-expression tree deeper than the cap.
            # Raised as ``_ValueError`` so ``language_extension`` turns
            # it into a clean ``TransformError`` match rather than an
            # internal traceback.
            raise _ValueError(
                "Fn::FindInMap nested beyond the maximum supported depth",
                obj,
            )
        _hash = get_hash(obj)
        if isinstance(obj, _SCALAR_TYPES):
            return _ForEachValue(_hash, obj)
        if isinstance(obj, dict):
            if len(obj) != 1:
                raise _ValueError("Object must have only one key", obj)

            for k, v in obj.items():
                if k == "Ref":
                    return _ForEachValueRef(_hash, v)
                if k == "Fn::FindInMap":
                    return _ForEachValueFnFindInMap(_hash, v, _depth=_depth + 1)
                if k == "Fn::If":
                    return _ForEachValueFnIf(_hash, v)

        raise _TypeError(f"Unsupported value {obj!r}", obj)

    # pylint: disable=unused-argument
    def value(
        self, cfn, params: Mapping[str, Any] | None = None, only_params: bool = False
    ):
        return self._value

    @property
    def hash(self):
        return self._hash

    def _cache_key(
        self,
        cfn: Any,
        params: Mapping[str, Any] | None,
        only_params: bool,
    ) -> tuple | None:
        """Build a stable key for the per-instance value cache.

        Returns ``None`` when the caller's state is not safely hashable;
        in that case the caller should skip the cache rather than fall
        back on an unreliable key.
        """
        try:
            params_hash = get_hash(params) if params else ""
        except Exception:  # pylint: disable=broad-exception-caught
            return None
        return (id(cfn), params_hash, bool(only_params))


class _FnFindInMapDefaultValue(_ForEachValue):
    def __init__(self, _hash: str, value: Any = None, _depth: int = 1) -> None:
        super().__init__(_hash, value)
        if not isinstance(value, dict):
            raise _TypeError(
                "Fn::FindInMap parameter must be an object with key 'DefaultValue'",
                value,
            )
        if len(value) != 1:
            raise _ValueError(
                "Fn::FindInMap parameter only supports 'DefaultValue'", value
            )

        for k, v in value.items():
            if k != "DefaultValue":
                raise _ValueError(
                    "Fn::FindInMap parameter only supports 'DefaultValue'", value
                )
            if isinstance(v, list):
                self._value = [_ForEachValue.create(a, _depth=_depth) for a in v]
                return
            self._value = _ForEachValue.create(v, _depth=_depth)

    def value(
        self, cfn, params: Mapping[str, Any] | None = None, only_params: bool = False
    ):
        if params is None:
            params = {}

        if isinstance(self._value, list):
            return [v.value(cfn, params, only_params) for v in self._value]
        return self._value.value(cfn, params, only_params)


class _ForEachValueFnFindInMap(_ForEachValue):
    def __init__(self, _hash: str, obj: Any, _depth: int = 1) -> None:
        super().__init__(_hash)
        if not isinstance(obj, list):
            raise _TypeError("Fn::FindInMap should be a list", obj)

        if len(obj) not in [3, 4]:
            raise _ValueError("Fn::FindInMap requires a list of 3 or 4 values", obj)

        # ``_depth`` is forwarded so a nested Fn::FindInMap in any of the
        # three positional slots counts against the overall depth cap
        # enforced in ``_ForEachValue.create``.
        self._map = [
            _ForEachValue.create(obj[0], _depth=_depth),
            _ForEachValue.create(obj[1], _depth=_depth),
            _ForEachValue.create(obj[2], _depth=_depth),
        ]
        if len(obj) == 4:
            self._map.append(
                _FnFindInMapDefaultValue(get_hash(obj[3]), obj[3], _depth=_depth)
            )

        self._obj = obj

    def value(
        self,
        cfn: Any,
        params: Mapping[str, Any] | None = None,
        only_params: bool = False,
        default_on_resolver_failure: bool = True,
    ) -> Any:
        if params is None:
            params = {}

        # Memoize the full result of this call.  The resolver is pure
        # with respect to (cfn, params, only_params, default_on_resolver_failure)
        # and is called repeatedly inside the Mappings scan below as
        # well as from recursive parent FindInMaps.  Without this cache
        # a chain of nested Fn::FindInMaps costs O((M*K)**depth).
        cache_key: tuple | None = None
        key_base = self._cache_key(cfn, params, only_params)
        if key_base is not None:
            cache_key = key_base + (bool(default_on_resolver_failure),)
            cached = self._value_cache.get(cache_key, _CACHE_MISS)
            if cached is not _CACHE_MISS:
                if isinstance(cached, _ResolveError):
                    raise cached
                return cached

        try:
            result = self._value_impl(
                cfn, params, only_params, default_on_resolver_failure
            )
        except _ResolveError as exc:
            if cache_key is not None:
                self._value_cache[cache_key] = exc
            raise
        if cache_key is not None:
            self._value_cache[cache_key] = result
        return result

    def _value_impl(
        self,
        cfn: Any,
        params: Mapping[str, Any],
        only_params: bool,
        default_on_resolver_failure: bool,
    ) -> Any:
        # Shallow copy: only the list slots are reassigned below (the
        # elements themselves are never mutated), so there is no need
        # for the per-call ``deepcopy`` that used to dominate the
        # profile.
        t_map = list(self._map)
        mapping = None
        try:
            mapping = cfn.template.get("Mappings", {}).get(
                t_map[0].value(cfn, params, only_params)
            )
        except Exception:  # pylint: disable=broad-exception-caught
            if len(cfn.template.get("Mappings", {}).keys()) == 1:
                mapping = cfn.template.get("Mappings", {}).get(
                    list(cfn.template.get("Mappings", {}).keys())[0]
                )

        try:
            if mapping is None and isinstance(
                t_map[1].value(cfn, params, only_params), str
            ):
                # Hoist the child resolution out of the loop; its value
                # is deterministic for fixed (cfn, params) and
                # recomputing it per iteration contributed to the
                # exponential cost called out in the finding.
                # ``only_params`` is intentionally left at its default
                # here to preserve the original behaviour (the outer
                # guard uses ``only_params``, the inner comparison did
                # not).
                t_map_1_value = t_map[1].value(cfn, params)
                for k, v in cfn.template.get("Mappings", {}).items():
                    if isinstance(v, dict):
                        if t_map_1_value in v:
                            t_map[0] = _ForEachValue.create(k)
                            mapping = v
                            break
        except _ResolveError:
            pass

        try:
            if mapping is None and isinstance(
                t_map[2].value(cfn, params, only_params), str
            ):
                # Hoist out of the double loop (see note above); this is
                # the specific spot called out in the finding.
                t_map_2_value_outer = t_map[2].value(cfn, params, only_params)
                for m1, mv1 in cfn.template.get("Mappings", {}).items():
                    if isinstance(mv1, dict):
                        for k1, kv1 in mv1.items():
                            if isinstance(kv1, dict):
                                if t_map_2_value_outer in kv1:
                                    t_map[1] = _ForEachValue.create(k1)
                                    t_map[0] = _ForEachValue.create(m1)
                                    mapping = mv1
                                    break
        except _ResolveError:
            pass

        if mapping:
            try:
                t_map[1].value(cfn, params, only_params)
                # continue to resolution below
            except _ResolveError:
                try:
                    t_map_2_value = t_map[2].value(cfn, params, only_params)
                    max_length = -1
                    for k, v in mapping.items():
                        if isinstance(v, dict):
                            if t_map_2_value in v:
                                if (
                                    isinstance(v[t_map_2_value], list)
                                    and len(v[t_map_2_value]) <= max_length
                                ):
                                    continue
                                if isinstance(t_map[1], _ForEachValueRef):
                                    if t_map[1]._ref._value == "AWS::AccountId":
                                        global _ACCOUNT_ID
                                        _ACCOUNT_ID = k
                                t_map[1] = _ForEachValue.create(k)
                                if isinstance(v[t_map_2_value], list):
                                    max_length = len(v[t_map_2_value])
                except _ResolveError:
                    pass

        if mapping:
            try:
                value = mapping.get(t_map[1].value(cfn, params, only_params), {}).get(
                    t_map[2].value(cfn, params, only_params)
                )
                if value is None:
                    raise _ResolveError("Can't resolve Fn::FindInMap", self._obj)
                return value
            except _ResolveError as e:
                if len(self._map) == 4 and default_on_resolver_failure:
                    return self._map[3].value(cfn, params, only_params)
                # no default value and map 1 exists
                try:
                    if isinstance(
                        t_map[2], (_ForEachValueRef, _ForEachValueFnFindInMap)
                    ):
                        for _, v in mapping.get(
                            t_map[1].value(cfn, params, only_params), {}
                        ).items():
                            if isinstance(v, list):
                                return v
                except _ResolveError:
                    pass
                raise _ResolveError("Can't resolve Fn::FindInMap", self._obj) from e

        if len(self._map) == 4 and default_on_resolver_failure:
            return self._map[3].value(cfn, params, only_params)
        raise _ResolveError("Can't resolve Fn::FindInMap", self._obj)


class _ForEachValueFnIf(_ForEachValue):
    def __init__(self, _hash: str, obj: Any) -> None:
        super().__init__(_hash)
        if not isinstance(obj, (list)):
            raise _TypeError("Fn::If should be a list of 3 elements", obj)

        if len(obj) != 3:
            raise _TypeError("Fn::If should be a list of 3 elements", obj)
        self._condition = _ForEachValue.create(obj[0])
        self._obj = obj

    # pylint: disable=too-many-return-statements
    def value(
        self,
        cfn: Any,
        params: Mapping[str, Any] | None = None,
        only_params: bool = False,
    ) -> Any:
        raise _ResolveError("Can't resolve Fn::If", self._obj)


class _ForEachValueRef(_ForEachValue):
    def __init__(self, _hash: str, obj: Any) -> None:
        super().__init__(_hash)
        if not isinstance(obj, (str, dict)):
            raise _TypeError("Fn::Ref should be a list", obj)

        self._ref = _ForEachValue.create(obj)
        self._obj = obj

    # pylint: disable=too-many-return-statements
    def value(
        self,
        cfn: Any,
        params: Mapping[str, Any] | None = None,
        only_params: bool = False,
    ) -> Any:
        if params is None:
            params = {}
        v = self._ref.value(cfn, params)

        if not isinstance(v, str):
            raise _ResolveError("Can't resolve Fn::Ref", self._obj)

        if v in params:
            return params[v]

        if only_params:
            raise _ResolveError("Can't resolve Fn::Ref", self._obj)

        region = cfn.regions[0]
        account_id = "123456789012"
        partition = "aws"
        if region in ("us-gov-east-1", "us-gov-west-1"):
            partition = "aws-us-gov"
        if region in ("cn-north-1", "cn-northwest-1"):
            partition = "aws-cn"
        if v == "AWS::Region":
            return region

        if v == "AWS::AccountId":
            if _ACCOUNT_ID is None:
                raise _ResolveError("Can't resolve Fn::Ref", self._obj)
            return _ACCOUNT_ID

        if v == "AWS::NotificationARNs":
            return [f"arn:{partition}:sns:{region}:{account_id}:notification"]

        if v == "AWS::NoValue":
            return None

        if v == "AWS::Partition":
            return partition

        if v == "AWS::StackId":
            return (
                f"arn:{partition}:cloudformation:"
                f"{region}:{account_id}:"
                "stack/teststack/51af3dc0-da77-11e4-872e-1234567db123"
            )

        if v == "AWS::StackName":
            return "teststack"

        if v == "AWS::URLSuffix":
            if region in ("cn-north-1", "cn-northwest-1"):
                return "amazonaws.com.cn"

            return "amazonaws.com"

        p = cfn.template.get("Parameters", {}).get(v)
        if not p:
            raise _ResolveError("Can't resolve Fn::Ref", self._obj)
        t = p.get("Type", "String")
        if t.startswith("AWS::SSM::Parameter"):
            raise _ResolveError("Can't resolve Fn::Ref", self._obj)
        default = p.get("Default")
        if default:
            if "List" in t:
                return [x.strip() for x in default.split(",")]
            return default
        allowed_values = p.get("AllowedValues", [])
        if len(allowed_values) > 0:
            if "List" in t:
                return [x.strip() for x in allowed_values[0].split(",")]
            return allowed_values[0]

        if "List" in t:
            return [{"Fn::Select": [0, {"Ref": v}]}, {"Fn::Select": [1, {"Ref": v}]}]

        raise _ResolveError("Can't resolve Fn::Ref", self._obj)


class _ForEachCollection:
    def __init__(self, obj: Any) -> None:
        self._collection: list[_ForEachValue] | None = None
        self._obj = obj
        self._fn: _ForEachValue | None = None
        if isinstance(obj, list):
            self._collection = []
            self._string = obj
            for item in obj:
                self._collection.append(_ForEachValue.create(item))
            return
        if isinstance(obj, dict):
            self._fn = _ForEachValue.create(obj)
            return
        raise _TypeError("Collection must be a list or an object", obj)

    def values(
        self,
        cfn: Any,
        collection_cache: MutableMapping[str, Any],
        params: MutableMapping[str, Any],
    ) -> Iterator[str | dict[Any, Any]]:
        if self._collection:
            for item in self._collection:
                try:
                    yield item.value(cfn, {}, False)
                except _ResolveError:
                    v = "".join(random.choices(string.ascii_letters, k=_N))  # nosec
                    collection_cache[item.hash] = v
                    yield v
            return
        if self._fn:
            try:
                values = self._fn.value(cfn, params, False)
                if values is not None:
                    if isinstance(values, list):
                        for value in values:
                            if isinstance(value, (str, dict)):
                                yield value
                            else:
                                raise _ValueError(
                                    "Fn::ForEach collection value "
                                    f"must be a {_SCALAR_TYPES!r}",
                                    self._obj,
                                )
                        return
                    raise _ValueError(
                        "Fn::ForEach collection must return a list", self._obj
                    )
            except _ResolveError:
                if self._fn.hash in collection_cache:
                    yield from iter(collection_cache[self._fn.hash])
                else:
                    collection_cache[self._fn.hash] = []
                    for _ in range(0, 2):
                        v = "".join(random.choices(string.ascii_letters, k=_N))  # nosec
                        collection_cache[self._fn.hash].append(v)
                        yield v
                return
        raise _ResolveError("Fn::ForEach could not be resolved", self._obj)


class _ForEachOutput:
    def __init__(self, obj: Any) -> None:
        if isinstance(obj, dict):
            self._output = obj
            return
        raise _TypeError("Output must be a dict", obj)

    def value(self) -> Any:
        return self._output


class _ForEach:
    def __init__(
        self, key: str, value: Any, collection_cache: MutableMapping[str, str]
    ) -> None:
        self._key = key
        self._collection_cache: MutableMapping[str, str] = collection_cache
        if not isinstance(value, list):
            raise _TypeError("Fn::ForEach values must be a list of 3 elements", key)

        if not len(value) == 3:
            raise _TypeError("Fn::ForEach values must be a list of 3 elements", key)

        self._identifier = _ForEachValue.create(value[0])
        self._collection = _ForEachCollection(value[1])
        self._output = _ForEachOutput(value[2])

    def items(
        self, cfn: Any, params: MutableMapping[str, Any]
    ) -> Iterator[str | dict[str, str]]:
        items = self._collection.values(cfn, self._collection_cache, params)
        yield from iter(items)
