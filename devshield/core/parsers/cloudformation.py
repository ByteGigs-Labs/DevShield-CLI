"""Load CloudFormation templates, whose YAML tags (!Ref, !Sub) SafeLoader rejects."""

from __future__ import annotations

import json
from typing import Any

import yaml


class _Loader(yaml.SafeLoader):
    pass


def _any_tag(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)  # type: ignore[arg-type]


_Loader.add_multi_constructor("!", _any_tag)


def load_template(text: str, is_json: bool = False) -> dict[str, Any] | None:
    try:
        data = json.loads(text) if is_json else yaml.load(text, Loader=_Loader)  # noqa: S506
    except (ValueError, yaml.YAMLError):
        return None
    return data if isinstance(data, dict) else None
