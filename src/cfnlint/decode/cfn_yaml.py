"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

# Code is taken from jsonschema package and adapted CloudFormation use
# https://github.com/yaml/pyyaml/blob/a2d19c0234866dc9d4d55abf3009699c258bb72f/lib/yaml/scanner.py#L46
"""

from __future__ import annotations

import bisect
import fileinput
import logging
import sys
from typing import Any, NamedTuple

from yaml import AliasToken, MappingNode, SafeLoader, ScalarNode, SequenceNode, scan

try:
    from yaml import CSafeLoader

    FastLoader = CSafeLoader  # type: ignore
except ImportError:
    FastLoader = SafeLoader  # type: ignore

from yaml.constructor import ConstructorError, SafeConstructor
from yaml.parser import ParserError
from yaml.scanner import ScannerError

from cfnlint.decode.mark import Mark
from cfnlint.decode.node import dict_node, list_node, str_node
from cfnlint.rules import Match
from cfnlint.rules.errors import ParseError

UNCONVERTED_SUFFIXES = ["Ref", "Condition"]
FN_PREFIX = "Fn::"

# CloudFormation rejects YAML aliases; the AWS CLI "package" command and SAM
# resolve them client-side, so cfn-lint resolves them too.  A small template
# using nested aliases ("billion laughs") can expand to an exponentially large
# structure that exhausts CPU in any consumer that walks the template.  Reject
# templates whose alias-resolved size exceeds this many nodes.
_MAX_EXPANDED_NODES = 250_000

# Reject source templates larger than this.  cfn-lint is routinely invoked on
# attacker-supplied templates (pre-commit hooks, CI linting of fork PRs, IDE
# plugins, SaaS pipelines via cfnlint.api.lint), and the YAML scanner's cost
# scales with input size.  Legitimate CloudFormation templates are capped at
# 1 MiB by the service itself, so refusing larger inputs is safe.
_MAX_TEMPLATE_BYTES = 5 * 1024 * 1024

# Hard cap on the number of alias tokens processed when recording YAML alias
# locations for rule W1101.  A single attacker-written file can contain an
# arbitrary number of aliases; refuse to process more than this and emit one
# aggregate match for the overflow, as `_guard_alias_expansion` already does
# for alias-resolved node count.
_MAX_ALIAS_TOKENS = 10_000

LOGGER = logging.getLogger(__name__)


class YamlAlias(NamedTuple):
    """A YAML alias ("*name") used in the source template"""

    name: str
    path: list[str | int]
    start_mark: Mark
    end_mark: Mark


class CfnParseError(ConstructorError):
    """
    Error thrown when the template contains Cfn Error
    """

    def __init__(self, filename, errors):
        if isinstance(errors, Match):
            errors = [errors]

        # Call the base class constructor with the parameters it needs
        super().__init__(errors[0].message)

        # Now for your custom code...
        self.filename = filename
        self.matches = errors


def build_match(filename, message, line_number, column_number, key):
    return Match.create(
        message=message,
        filename=filename,
        rule=ParseError(),
        linenumber=line_number + 1,
        columnnumber=column_number + 1,
        linenumberend=line_number + 1,
        columnnumberend=column_number + 1 + len(key),
    )


class NodeConstructor(SafeConstructor):
    """
    Node Constructors for loading different types in Yaml
    """

    def __init__(self, filename):
        # Call the base class constructor
        super().__init__()
        self.filename = filename

    def flatten_mapping(self, node):
        # Rewrote to handle merging and overwriting keys
        if any(key_node.tag == "tag:yaml.org,2002:merge" for key_node, _ in node.value):
            super().flatten_mapping(node)
            setattr(node, "using_merge", True)
        super().flatten_mapping(node)

    # To support lazy loading, the original constructors first yield
    # an empty object, then fill them in when iterated. Due to
    # laziness we omit this behaviour (and will only do "deep
    # construction") by first exhausting iterators, then yielding
    # copies.
    def construct_yaml_map(self, node):
        # Check for duplicate keys on the current level, this is not desirable
        # because a dict does not support this. It overwrites it with the last
        # occurance, which can give unexpected results
        mapping = {}
        self.flatten_mapping(node)
        matches = []
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, False)
            value = self.construct_object(value_node, False)

            if key is None:
                raise CfnParseError(
                    self.filename,
                    [
                        build_match(
                            filename=self.filename,
                            message=(
                                f"Null key {key_node.value!r} not supported "
                                f"(line {key_node.start_mark.line + 1})"
                            ),
                            line_number=key_node.start_mark.line,
                            column_number=key_node.start_mark.column,
                            key=key_node.value,
                        ),
                    ],
                )
            if not getattr(node, "using_merge", False):
                for key_dup in mapping:
                    if key_dup == key:
                        if matches:
                            matches.append(
                                build_match(
                                    filename=self.filename,
                                    message=(
                                        f"Duplicate found {key!r} (line"
                                        f" {key_node.start_mark.line + 1})"
                                    ),
                                    line_number=key_node.start_mark.line,
                                    column_number=key_node.start_mark.column,
                                    key=key,
                                )
                            )
                        else:
                            matches.extend(
                                [
                                    build_match(
                                        filename=self.filename,
                                        message=(
                                            f"Duplicate found {key!r} (line"
                                            f" {key_dup.start_mark.line + 1})"
                                        ),
                                        line_number=key_dup.start_mark.line,
                                        column_number=key_dup.start_mark.column,
                                        key=key,
                                    ),
                                    build_match(
                                        filename=self.filename,
                                        message=(
                                            f"Duplicate found {key!r} (line"
                                            f" {key_node.start_mark.line + 1})"
                                        ),
                                        line_number=key_node.start_mark.line,
                                        column_number=key_node.start_mark.column,
                                        key=key,
                                    ),
                                ],
                            )
            try:
                mapping[key] = value
            except Exception as exc:
                raise CfnParseError(
                    self.filename,
                    [
                        build_match(
                            filename=self.filename,
                            message=(
                                f'Unhashable type "{key}" (line'
                                f" {key.start_mark.line + 1})"
                            ),
                            line_number=key.start_mark.line,
                            column_number=key.start_mark.column,
                            key=key,
                        ),
                    ],
                ) from exc

        if matches:
            raise CfnParseError(
                self.filename,
                matches,
            )

        (obj,) = SafeConstructor.construct_yaml_map(self, node)

        using_merge = False if not hasattr(node, "using_merge") else node.using_merge
        return dict_node(obj, node.start_mark, node.end_mark, using_merge)

    def construct_yaml_str(self, node):
        obj = SafeConstructor.construct_yaml_str(self, node)
        assert isinstance(obj, (str))
        return str_node(obj, node.start_mark, node.end_mark)

    def construct_yaml_seq(self, node):
        (obj,) = SafeConstructor.construct_yaml_seq(self, node)
        assert isinstance(obj, list)
        return list_node(obj, node.start_mark, node.end_mark)

    def construct_getatt(self, node):
        """
        Reconstruct !GetAtt into a list
        """
        if isinstance(node.value, (str)):
            return list_node(node.value.split(".", 1), node.start_mark, node.end_mark)
        if isinstance(node.value, list):
            if any(isinstance(value, tuple) for value in node.value):
                return dict_node(
                    self.construct_object(
                        MappingNode(
                            tag="tag:yaml.org,2002:map",
                            value=node.value,
                            start_mark=node.start_mark,
                            end_mark=node.end_mark,
                        ),
                        deep=True,
                    )
                )
            else:
                return list_node(
                    [self.construct_object(child, deep=True) for child in node.value],
                    node.start_mark,
                    node.end_mark,
                )
        raise ValueError(f"Unexpected GetAtt format: {type(node.value)}")


NodeConstructor.add_constructor(  # type: ignore
    "tag:yaml.org,2002:map", NodeConstructor.construct_yaml_map
)

NodeConstructor.add_constructor(  # type: ignore
    "tag:yaml.org,2002:str", NodeConstructor.construct_yaml_str
)

NodeConstructor.add_constructor(  # type: ignore
    "tag:yaml.org,2002:seq", NodeConstructor.construct_yaml_seq
)


class CfnFullLoader(FastLoader, NodeConstructor):
    """
    Custom FullLoader that integrates NodeConstructor functionality
    """

    def __init__(self, stream, filename):
        FastLoader.__init__(self, stream)
        NodeConstructor.__init__(self, filename)


# Register NodeConstructor methods with CfnFullLoader
CfnFullLoader.add_constructor(  # type: ignore[type-var]
    "tag:yaml.org,2002:map", NodeConstructor.construct_yaml_map
)
CfnFullLoader.add_constructor(  # type: ignore[type-var]
    "tag:yaml.org,2002:str", NodeConstructor.construct_yaml_str
)
CfnFullLoader.add_constructor(  # type: ignore[type-var]
    "tag:yaml.org,2002:seq", NodeConstructor.construct_yaml_seq
)


def multi_constructor(loader: CfnFullLoader, tag_suffix, node):
    """
    Deal with !Ref style function format
    """

    if tag_suffix not in UNCONVERTED_SUFFIXES:
        tag_suffix = f"{FN_PREFIX}{tag_suffix}"

    if tag_suffix == "Fn::GetAtt":
        return dict_node(
            {tag_suffix: loader.construct_getatt(node)}, node.start_mark, node.end_mark
        )
    elif isinstance(node, ScalarNode):
        return dict_node(
            {tag_suffix: loader.construct_scalar(node)}, node.start_mark, node.end_mark
        )
    elif isinstance(node, SequenceNode):
        return dict_node(
            {tag_suffix: loader.construct_sequence(node, True)},
            node.start_mark,
            node.end_mark,
        )
    elif isinstance(node, MappingNode):
        return dict_node(
            {tag_suffix: loader.construct_mapping(node, True)},
            node.start_mark,
            node.end_mark,
        )

    raise Exception(f"Bad tag: !{tag_suffix}")


def _guard_alias_expansion(template, filename):
    """Reject templates whose YAML aliases resolve to an excessive size.

    Computes the alias-resolved (flattened) node count in O(distinct nodes)
    using memoization on object identity, and raises CfnParseError if it
    exceeds _MAX_EXPANDED_NODES.  This bounds YAML alias amplification at the
    single point where the template is loaded, protecting every downstream
    consumer that walks the template.
    """
    size_memo: dict[int, int] = {}

    def size(node):
        nid = id(node)
        cached = size_memo.get(nid)
        if cached is not None:
            return cached
        if isinstance(node, dict):
            children = node.values()
        elif isinstance(node, list):
            children = node
        else:
            size_memo[nid] = 1
            return 1
        total = 1
        for child in children:
            total += size(child)
            if total > _MAX_EXPANDED_NODES:
                raise CfnParseError(
                    filename,
                    [
                        build_match(
                            filename=filename,
                            message=(
                                "Template resolves to more than "
                                f"{_MAX_EXPANDED_NODES} nodes once YAML aliases "
                                "are expanded; this is not supported and may "
                                "indicate YAML alias amplification"
                            ),
                            line_number=0,
                            column_number=0,
                            key="",
                        )
                    ],
                )
        size_memo[nid] = total
        return total

    size(template)


def _position(mark) -> tuple[int, int]:
    return (mark.line, mark.column)


def _spans(node: Any, position: tuple[int, int]) -> bool:
    """Whether position falls inside the source span of a decoded node"""
    start = getattr(node, "start_mark", None)
    end = getattr(node, "end_mark", None)
    if start is None or end is None:
        return False
    return _position(start) <= position < _position(end)


def _alias_path(template: Any, mark) -> list[str | int]:
    """Find the template path of the value an alias at mark stands in for.

    An alias resolves to the anchored node itself, so the aliased value
    carries the anchor's marks, not the alias's.  Instead descend from the
    root through the nodes whose source span contains the alias.  Within a
    mapping, the entry holding the alias is the last key that starts before
    it; keys from a merge ("<<") lie outside the mapping's span and are
    skipped.  Stops at the deepest node that can be located.

    This single-alias helper re-walks the template per call and is kept for
    backwards compatibility; the batch path used by `_find_aliases` goes
    through `_build_entry_index` + `_alias_path_from_index`, which is
    O(log nodes) per alias instead of O(width) per alias.
    """
    position = _position(mark)
    path: list[str | int] = []
    node = template
    while True:
        if isinstance(node, dict):
            # Keys without marks (e.g. "Fn::Sub" from a "!Sub" tag) start
            # where their mapping does
            node_start = getattr(node, "start_mark")
            keys = [
                (_position(getattr(key, "start_mark", node_start)), key) for key in node
            ]
            keys = [
                (start, key)
                for start, key in keys
                if start <= position and _spans(node, start)
            ]
            if not keys:
                return path
            _, key = max(keys, key=lambda entry: entry[0])
            path.append(key)
            child = node[key]
        elif isinstance(node, list):
            index = next(
                (i for i, item in enumerate(node) if _spans(item, position)), None
            )
            if index is None:
                return path
            path.append(index)
            child = node[index]
        else:
            return path

        if not _spans(child, position):
            return path
        node = child


# Sentinel for `_build_entry_index` to represent "no end" (open-ended span).
_OPEN_END: tuple[int, int] = (sys.maxsize, sys.maxsize)


def _build_entry_index(
    template: Any,
) -> tuple[list[tuple[int, int]], list[tuple[int, int]], list[list[str | int]]]:
    """Build a sorted index of value-entry source spans for one template.

    Walks the decoded tree once (bounded by `_MAX_EXPANDED_NODES` via the
    identity-memoized guard that runs just before this) and records, for every
    addressable value site, a tuple of (start_position, end_position, path).
    Shared sub-trees (reachable through more than one alias) are visited once
    using object identity.  The resulting lists are sorted by `start_position`,
    enabling O(log nodes) lookup per alias via `_alias_path_from_index`.
    """
    starts: list[tuple[int, int]] = []
    ends: list[tuple[int, int]] = []
    paths: list[list[str | int]] = []
    visited: set[int] = set()

    def end_of(node: Any, fallback: tuple[int, int]) -> tuple[int, int]:
        # Scalars from the YAML loader (int, bool, None, custom int-ish
        # literals) carry no `end_mark`.  Fall back to the enclosing span so a
        # scalar entry doesn't swallow unrelated later aliases.
        end = getattr(node, "end_mark", None)
        if end is None:
            return fallback
        return _position(end)

    def record(start: tuple[int, int], end: tuple[int, int], path: list[str | int]):
        # Only well-formed, non-empty intervals contribute useful info.
        if start < end:
            starts.append(start)
            ends.append(end)
            paths.append(path)

    def walk(node: Any, path: list[str | int], parent_end: tuple[int, int]) -> None:
        nid = id(node)
        if nid in visited:
            return
        if isinstance(node, dict):
            visited.add(nid)
            node_end_mark = getattr(node, "end_mark", None)
            if node_end_mark is not None:
                container_end = _position(node_end_mark)
            else:
                container_end = parent_end
            node_start_mark = getattr(node, "start_mark", None)
            node_start_pos = (
                _position(node_start_mark) if node_start_mark is not None else (0, 0)
            )
            # Pre-compute the start positions of each (key, child) so a scalar
            # child's span can be bounded by the next sibling's start.
            key_list = list(node)
            key_starts: list[tuple[int, int]] = []
            for key in key_list:
                key_mark = getattr(key, "start_mark", None)
                key_starts.append(
                    _position(key_mark) if key_mark is not None else node_start_pos
                )
            for i, key in enumerate(key_list):
                start = key_starts[i]
                child = node[key]
                # Bound a markless child by (a) its own end_mark if present,
                # (b) the next sibling's start, or (c) the container's end.
                sibling_bound = (
                    key_starts[i + 1] if i + 1 < len(key_starts) else container_end
                )
                end = end_of(child, sibling_bound)
                # If the child is itself the resolved target of an alias used
                # here, its end_mark points back to where the anchor was
                # defined -- which is behind `start`, giving an empty
                # interval.  Fall back to the sibling bound so the entry
                # still contains the key's own source span.
                if end <= start:
                    end = sibling_bound
                child_path = path + [key]
                record(start, end, child_path)
                walk(child, child_path, container_end)
        elif isinstance(node, list):
            visited.add(nid)
            node_end_mark = getattr(node, "end_mark", None)
            if node_end_mark is not None:
                container_end = _position(node_end_mark)
            else:
                container_end = parent_end
            for index, item in enumerate(node):
                # An aliased list item carries the anchor's marks, not its own
                # source position, so an entry built from `item.start_mark`
                # cannot reliably locate the alias.  Only emit entries whose
                # span lies within the enclosing list -- aliased items
                # therefore fall through to the list-level entry, which is
                # the deepest path we can honestly report for them.
                child_path = path + [index]
                item_start = getattr(item, "start_mark", None)
                item_end = getattr(item, "end_mark", None)
                node_start = getattr(node, "start_mark", None)
                node_start_pos = (
                    _position(node_start) if node_start is not None else (0, 0)
                )
                if item_start is not None and item_end is not None:
                    item_start_pos = _position(item_start)
                    item_end_pos = _position(item_end)
                    if (
                        item_start_pos >= node_start_pos
                        and item_end_pos <= container_end
                    ):
                        record(item_start_pos, item_end_pos, child_path)
                walk(item, child_path, container_end)
        # Scalars contribute no entries beyond their parent's record.

    walk(template, [], _OPEN_END)
    # Sort entries by start position while keeping (start, end, path) aligned.
    order = sorted(range(len(starts)), key=starts.__getitem__)
    starts = [starts[i] for i in order]
    ends = [ends[i] for i in order]
    paths = [paths[i] for i in order]
    return starts, ends, paths


def _alias_path_from_index(
    index: tuple[list[tuple[int, int]], list[tuple[int, int]], list[list[str | int]]],
    mark,
) -> list[str | int]:
    """Return the path of the deepest template entry whose source span
    contains the alias token at `mark`, using the pre-sorted entry index
    produced by `_build_entry_index`.

    YAML entry spans are properly nested (a child's span lies inside its
    parent's), so after bisecting for the largest `start <= position` we need
    at most O(depth) steps backwards to find an entry whose `end > position`.
    In the common degenerate shape (many aliases inside a single wide
    mapping) the bisected candidate is already the correct entry, giving
    O(log nodes) per alias.
    """
    starts, ends, paths = index
    position = _position(mark)
    # Rightmost entry with start <= position
    i = bisect.bisect_right(starts, position) - 1
    while i >= 0:
        if ends[i] > position:
            return list(paths[i])
        i -= 1
    return []


def _find_aliases(yaml_string: str, template: Any) -> list[YamlAlias]:
    """Record where each YAML alias is used in yaml_string.

    Aliases are resolved while the document is composed, which the C loader
    does natively, so the decoded template cannot tell an aliased value from
    a literal one.  Scan the tokens to recover each alias's own location.

    A single sorted (start -> path) index is built once per template and
    binary-searched per alias, bounding total work at O(nodes log nodes +
    aliases log nodes) rather than O(aliases x width).  Processing stops at
    `_MAX_ALIAS_TOKENS` with one aggregate overflow entry so an attacker
    cannot force unbounded work via an unbounded number of alias tokens.
    """
    aliases: list[YamlAlias] = []
    index = _build_entry_index(template)
    overflow = False
    for token in scan(yaml_string, Loader=FastLoader):
        if isinstance(token, AliasToken):
            if len(aliases) >= _MAX_ALIAS_TOKENS:
                overflow = True
                break
            aliases.append(
                YamlAlias(
                    name=token.value,
                    path=_alias_path_from_index(index, token.start_mark),
                    start_mark=Mark(token.start_mark.line, token.start_mark.column),
                    end_mark=Mark(token.end_mark.line, token.end_mark.column),
                )
            )
    if overflow:
        LOGGER.warning(
            "Template contains more than %d YAML aliases; only the first %d "
            "are reported for rule W1101",
            _MAX_ALIAS_TOKENS,
            _MAX_ALIAS_TOKENS,
        )
    return aliases


def loads(yaml_string, fname=None):
    """
    Load the given YAML string
    """
    # Enforce an upper bound on template size before any YAML parsing.  The
    # scanner's cost (anchor/alias handling in particular) scales with input
    # size, and a shared CI runner lint-ing an attacker-supplied template
    # should refuse pathologically large inputs rather than melting CPU.
    if (
        isinstance(yaml_string, (str, bytes, bytearray))
        and len(yaml_string) > _MAX_TEMPLATE_BYTES
    ):
        raise CfnParseError(
            fname,
            [
                build_match(
                    filename=fname,
                    message=(
                        f"Template exceeds the maximum supported size of "
                        f"{_MAX_TEMPLATE_BYTES} bytes"
                    ),
                    line_number=0,
                    column_number=0,
                    key="",
                )
            ],
        )
    try:
        loader = CfnFullLoader(yaml_string, fname)
        loader.add_multi_constructor("!", multi_constructor)

        template = loader.get_single_data()
        # Convert an empty file to an empty dict
        if template is None:
            template = dict_node({}, Mark(0, 0), Mark(0, 0))
        # A YAML alias ("*x") is only valid if a matching anchor ("&x") is
        # defined, so a source with no "&" cannot contain aliases and needs no
        # expansion check.  This keeps the guard off the hot path for the vast
        # majority of templates (which define no anchors) -- only templates
        # that actually use anchors pay for the walk.
        if isinstance(yaml_string, str) and "&" in yaml_string:
            _guard_alias_expansion(template, fname)
            # CloudFormation rejects aliases, so record where they are used
            # for rule W1101
            if isinstance(template, dict):
                aliases = _find_aliases(yaml_string, template)
                if aliases:
                    setattr(template, "yaml_aliases", aliases)
        return template
    except CfnParseError:
        raise
    except (ScannerError, ParserError):
        # Let YAML parsing errors bubble up so decode.py can handle JSON fallback
        raise
    except Exception as exc:
        raise CfnParseError(
            fname,
            [
                build_match(
                    filename=fname,
                    message=f"Template could not be parsed: {str(exc)}",
                    line_number=0,
                    column_number=0,
                    key="",
                )
            ],
        ) from exc


def load(filename):
    """
    Load the given YAML file
    """

    content = ""

    if (filename is None) and (not sys.stdin.isatty()):
        filename = "-"  # no filename provided, it's stdin
        fileinput_args = {"files": filename}
        if sys.version_info.major <= 3 and sys.version_info.minor >= 10:
            fileinput_args["encoding"] = "utf-8"
        with fileinput.input(**fileinput_args) as f:
            for line in f:
                content = content + line
    else:
        with open(filename, encoding="utf-8") as fp:
            content = fp.read()

    return loads(content, filename)
