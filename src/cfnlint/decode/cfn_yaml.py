"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

# Code is taken from jsonschema package and adapted CloudFormation use
# https://github.com/yaml/pyyaml/blob/a2d19c0234866dc9d4d55abf3009699c258bb72f/lib/yaml/scanner.py#L46
"""

from __future__ import annotations

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

# Hard cap on how deeply YAML merge keys ("<<") may nest during construction.
# Each level can in principle double its parent's materialised entry list, so
# we bound depth independently of the entry-count cap.
_MAX_MERGE_DEPTH = 100

# Hard cap on the input size (in bytes/characters) that cfn-lint will attempt
# to parse as YAML.  Templates larger than this are rejected before any
# construction work is done; this is well above every realistic
# CloudFormation template while still protecting against pathological inputs.
_MAX_TEMPLATE_SIZE = 50 * 1024 * 1024

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
        # Cumulative count of entries produced by merge-key expansion across
        # the whole document, and the current merge-nesting depth.  These
        # bound YAML merge-key ("<<") amplification *during* construction,
        # before the amplified entry list is materialised and iterated.
        self._merge_expanded_entries = 0
        self._merge_depth = 0

    def _raise_merge_amplification(self, node, message):
        start_mark = getattr(node, "start_mark", None)
        line = start_mark.line if start_mark is not None else 0
        column = start_mark.column if start_mark is not None else 0
        raise CfnParseError(
            self.filename,
            [
                build_match(
                    filename=self.filename,
                    message=message,
                    line_number=line,
                    column_number=column,
                    key="",
                )
            ],
        )

    def flatten_mapping(self, node):
        # Rewrote to handle merging and overwriting keys, and to bound YAML
        # merge-key ("<<") amplification during construction.
        #
        # PyYAML's SafeConstructor.flatten_mapping materialises the merged
        # mapping's entry list via ``node.value = merge + node.value``.  An
        # aliased anchor resolves to the *same* MappingNode object, so a
        # construct like ``<<: [*prev, *prev]`` doubles the entry list at
        # each level, producing 2**depth entries from a tiny template.  We
        # therefore reimplement the upstream algorithm here with three
        # guards: a cumulative entry-count cap across the whole document,
        # a merge-nesting depth cap, and de-duplication of merge sources by
        # node identity so a repeated reference inside one ``<<`` sequence
        # is counted (and merged) only once.
        if self._merge_depth >= _MAX_MERGE_DEPTH:
            self._raise_merge_amplification(
                node,
                (
                    "YAML merge-key nesting exceeds "
                    f"{_MAX_MERGE_DEPTH} levels; refusing to expand (possible "
                    "merge-key amplification)"
                ),
            )
        self._merge_depth += 1
        try:
            merge = []
            index = 0
            using_merge = False
            while index < len(node.value):
                key_node, value_node = node.value[index]
                if key_node.tag == "tag:yaml.org,2002:merge":
                    using_merge = True
                    del node.value[index]
                    if isinstance(value_node, MappingNode):
                        self.flatten_mapping(value_node)
                        merge.extend(value_node.value)
                        self._account_merge_entries(value_node, len(value_node.value))
                    elif isinstance(value_node, SequenceNode):
                        submerge = []
                        seen_ids: set[int] = set()
                        for subnode in value_node.value:
                            if not isinstance(subnode, MappingNode):
                                raise ConstructorError(
                                    "while constructing a mapping",
                                    node.start_mark,
                                    (
                                        "expected a mapping for merging, "
                                        f"but found {subnode.id}"
                                    ),
                                    subnode.start_mark,
                                )
                            # Reject repeated references to the same anchored
                            # mapping inside one ``<<`` sequence: merging the
                            # same node twice adds no information and is the
                            # primary amplification primitive.
                            if id(subnode) in seen_ids:
                                continue
                            seen_ids.add(id(subnode))
                            self.flatten_mapping(subnode)
                            submerge.append(subnode.value)
                        submerge.reverse()
                        for value in submerge:
                            merge.extend(value)
                            self._account_merge_entries(value_node, len(value))
                    else:
                        raise ConstructorError(
                            "while constructing a mapping",
                            node.start_mark,
                            (
                                "expected a mapping or list of mappings for "
                                f"merging, but found {value_node.id}"
                            ),
                            value_node.start_mark,
                        )
                elif key_node.tag == "tag:yaml.org,2002:value":
                    key_node.tag = "tag:yaml.org,2002:str"
                    index += 1
                else:
                    index += 1
            if merge:
                node.value = merge + node.value
            if using_merge:
                setattr(node, "using_merge", True)
        finally:
            self._merge_depth -= 1

    def _account_merge_entries(self, node, count):
        self._merge_expanded_entries += count
        if self._merge_expanded_entries > _MAX_EXPANDED_NODES:
            self._raise_merge_amplification(
                node,
                (
                    "YAML merge-key expansion produced more than "
                    f"{_MAX_EXPANDED_NODES} entries; refusing to expand "
                    "(possible merge-key amplification)"
                ),
            )

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


def _find_aliases(yaml_string: str, template: Any) -> list[YamlAlias]:
    """Record where each YAML alias is used in yaml_string.

    Aliases are resolved while the document is composed, which the C loader
    does natively, so the decoded template cannot tell an aliased value from
    a literal one.  Scan the tokens to recover each alias's own location.
    """
    aliases = []
    for token in scan(yaml_string, Loader=FastLoader):
        if isinstance(token, AliasToken):
            aliases.append(
                YamlAlias(
                    name=token.value,
                    path=_alias_path(template, token.start_mark),
                    start_mark=Mark(token.start_mark.line, token.start_mark.column),
                    end_mark=Mark(token.end_mark.line, token.end_mark.column),
                )
            )
    return aliases


def loads(yaml_string, fname=None):
    """
    Load the given YAML string
    """
    # Reject obviously oversized inputs before invoking the YAML parser.
    # This bounds the amount of work any single parse can do and complements
    # the merge-key amplification guards in NodeConstructor.flatten_mapping.
    if isinstance(yaml_string, (str, bytes, bytearray)):
        if len(yaml_string) > _MAX_TEMPLATE_SIZE:
            raise CfnParseError(
                fname,
                [
                    build_match(
                        filename=fname,
                        message=(
                            f"Template exceeds the maximum supported size of "
                            f"{_MAX_TEMPLATE_SIZE} bytes"
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
