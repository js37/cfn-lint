"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

from cfnlint.template.transforms._sam_globals import (
    _MAX_MERGE_DEPTH,
    _MAX_MERGED_LIST_LEN,
    _MAX_MERGED_NODES,
    SAMGlobalsMergeError,
    merge_globals,
)


class TestMerge:
    def test_dict_merge(self):
        template = {
            "Globals": {"Function": {"Environment": {"Variables": {"A": "1"}}}},
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {
                        "Environment": {"Variables": {"B": "2"}},
                    },
                }
            },
        }
        merge_globals(template)
        env = template["Resources"]["Fn"]["Properties"]["Environment"]["Variables"]
        assert env == {"A": "1", "B": "2"}

    def test_list_concat(self):
        template = {
            "Globals": {"Function": {"Layers": ["arn:layer1"]}},
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {"Layers": ["arn:layer2"]},
                }
            },
        }
        merge_globals(template)
        assert template["Resources"]["Fn"]["Properties"]["Layers"] == [
            "arn:layer1",
            "arn:layer2",
        ]

    def test_local_overrides_primitive(self):
        template = {
            "Globals": {"Function": {"Runtime": "python3.9"}},
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {"Runtime": "python3.12"},
                }
            },
        }
        merge_globals(template)
        assert template["Resources"]["Fn"]["Properties"]["Runtime"] == "python3.12"

    def test_intrinsic_local_wins(self):
        template = {
            "Globals": {"Function": {"Timeout": 30}},
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {"Timeout": {"Ref": "Param"}},
                }
            },
        }
        merge_globals(template)
        assert template["Resources"]["Fn"]["Properties"]["Timeout"] == {"Ref": "Param"}

    def test_intrinsic_global_replaced_by_local(self):
        template = {
            "Globals": {
                "Function": {"Environment": {"Fn::If": ["Cond", {"A": "1"}, {}]}}
            },
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {"Environment": {"Variables": {"B": "2"}}},
                }
            },
        }
        merge_globals(template)
        assert template["Resources"]["Fn"]["Properties"]["Environment"] == {
            "Variables": {"B": "2"}
        }

    def test_type_mismatch_local_wins(self):
        template = {
            "Globals": {"Function": {"Tags": {"Key": "Val"}}},
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {"Tags": "override"},
                }
            },
        }
        merge_globals(template)
        assert template["Resources"]["Fn"]["Properties"]["Tags"] == "override"

    def test_ignore_globals_star(self):
        template = {
            "Globals": {"Function": {"Runtime": "python3.9", "Timeout": 30}},
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "IgnoreGlobals": "*",
                    "Properties": {},
                }
            },
        }
        merge_globals(template)
        assert "Runtime" not in template["Resources"]["Fn"]["Properties"]

    def test_ignore_globals_list(self):
        template = {
            "Globals": {"Function": {"Runtime": "python3.9", "Timeout": 30}},
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "IgnoreGlobals": ["Runtime"],
                    "Properties": {},
                }
            },
        }
        merge_globals(template)
        props = template["Resources"]["Fn"]["Properties"]
        assert "Runtime" not in props
        assert props["Timeout"] == 30

    def test_no_globals_section(self):
        template = {
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {"Runtime": "python3.12"},
                }
            }
        }
        result = merge_globals(template)
        assert result is template

    def test_globals_not_dict(self):
        template = {"Globals": "invalid", "Resources": {}}
        result = merge_globals(template)
        assert result is template

    def test_resources_not_dict(self):
        template = {"Globals": {"Function": {"Runtime": "python3.9"}}}
        result = merge_globals(template)
        assert result is template

    def test_non_dict_resource_skipped(self):
        template = {
            "Globals": {"Function": {"Runtime": "python3.9"}},
            "Resources": {"Bad": "not-a-dict"},
        }
        merge_globals(template)
        assert template["Resources"]["Bad"] == "not-a-dict"

    def test_no_local_properties(self):
        template = {
            "Globals": {"Function": {"Runtime": "python3.9"}},
            "Resources": {
                "Fn": {"Type": "AWS::Serverless::Function"},
            },
        }
        merge_globals(template)
        assert template["Resources"]["Fn"]["Properties"]["Runtime"] == "python3.9"

    def test_unknown_globals_section_ignored(self):
        template = {
            "Globals": {"Unknown": {"Foo": "bar"}},
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {"Runtime": "python3.12"},
                }
            },
        }
        merge_globals(template)
        assert template["Resources"]["Fn"]["Properties"]["Runtime"] == "python3.12"

    def test_non_dict_globals_props_ignored(self):
        template = {
            "Globals": {"Function": "not-a-dict"},
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {"Runtime": "python3.12"},
                }
            },
        }
        merge_globals(template)
        assert template["Resources"]["Fn"]["Properties"]["Runtime"] == "python3.12"

    def test_api_globals(self):
        template = {
            "Globals": {"Api": {"TracingEnabled": True}},
            "Resources": {
                "MyApi": {
                    "Type": "AWS::Serverless::Api",
                    "Properties": {"StageName": "prod"},
                }
            },
        }
        merge_globals(template)
        props = template["Resources"]["MyApi"]["Properties"]
        assert props["TracingEnabled"] is True
        assert props["StageName"] == "prod"


class TestMergeBudgets:
    def test_node_budget_rejects_amplification(self):
        # A Globals subtree with many keys crossed with many matching
        # resources exceeds _MAX_MERGED_NODES and must be refused instead
        # of being materialised.
        n_keys = 2000
        n_resources = 2000
        globals_props = {f"k{i}": "v" for i in range(n_keys)}
        resources = {
            f"R{i}": {
                "Type": "AWS::Serverless::Function",
                "Properties": {},
            }
            for i in range(n_resources)
        }
        template = {
            "Globals": {"Function": globals_props},
            "Resources": resources,
        }
        try:
            merge_globals(template)
        except SAMGlobalsMergeError:
            return
        raise AssertionError("expected SAMGlobalsMergeError for amplification")

    def test_node_budget_allows_small_merge(self):
        # Projected nodes well under the budget: must still merge normally.
        template = {
            "Globals": {"Function": {"Runtime": "python3.12"}},
            "Resources": {
                f"R{i}": {"Type": "AWS::Serverless::Function", "Properties": {}}
                for i in range(5)
            },
        }
        merge_globals(template)
        for r in template["Resources"].values():
            assert r["Properties"]["Runtime"] == "python3.12"

    def test_recursion_depth_bounded(self):
        # A Globals subtree deeper than _MAX_MERGE_DEPTH that also appears
        # in a resource's Properties forces _merge to recurse beyond the
        # depth cap, which must be caught.
        globals_props: dict = {}
        cur = globals_props
        for _ in range(_MAX_MERGE_DEPTH + 5):
            cur["X"] = {}
            cur = cur["X"]
        local_props: dict = {}
        cur = local_props
        for _ in range(_MAX_MERGE_DEPTH + 5):
            cur["X"] = {}
            cur = cur["X"]
        template = {
            "Globals": {"Function": globals_props},
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": local_props,
                }
            },
        }
        try:
            merge_globals(template)
        except SAMGlobalsMergeError:
            return
        raise AssertionError("expected SAMGlobalsMergeError for depth")

    def test_list_concat_bounded(self):
        template = {
            "Globals": {
                "Function": {"Layers": ["x"] * _MAX_MERGED_LIST_LEN}
            },
            "Resources": {
                "Fn": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {"Layers": ["y", "z"]},
                }
            },
        }
        try:
            merge_globals(template)
        except SAMGlobalsMergeError:
            return
        raise AssertionError("expected SAMGlobalsMergeError for list length")

    def test_globals_not_mutated_when_ignore_list(self):
        # IgnoreGlobals=list must not pop keys from the shared Globals
        # subtree used by other resources.
        globals_props = {"Runtime": "python3.9", "Timeout": 30}
        template = {
            "Globals": {"Function": globals_props},
            "Resources": {
                "A": {
                    "Type": "AWS::Serverless::Function",
                    "IgnoreGlobals": ["Runtime"],
                    "Properties": {},
                },
                "B": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {},
                },
            },
        }
        merge_globals(template)
        assert globals_props == {"Runtime": "python3.9", "Timeout": 30}
        assert "Runtime" not in template["Resources"]["A"]["Properties"]
        assert template["Resources"]["B"]["Properties"]["Runtime"] == "python3.9"

    def test_budget_sanity(self):
        # Guardrail: constants exist and look sensible.
        assert _MAX_MERGED_NODES >= 1000
        assert _MAX_MERGE_DEPTH >= 10
        assert _MAX_MERGED_LIST_LEN >= 100
