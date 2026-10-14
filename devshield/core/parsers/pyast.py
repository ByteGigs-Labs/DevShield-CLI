"""Helpers for reading Python settings and config modules with the ast module."""

from __future__ import annotations

import ast
from typing import Any

MISSING: Any = object()


def parse_module(text: str) -> ast.Module | None:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None


def literal(node: ast.expr | None) -> Any:
    """The Python value of a literal expression, or MISSING when it is computed."""
    if node is None:
        return MISSING
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return MISSING


def module_assignments(tree: ast.Module) -> dict[str, tuple[ast.expr, int]]:
    """Top-level ``NAME = value`` assignments. The last assignment to a name wins."""
    found: dict[str, tuple[ast.expr, int]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = (node.value, node.lineno)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            found[node.target.id] = (node.value, node.lineno)
    return found


def secret_assignments(tree: ast.Module, names: frozenset[str]) -> list[tuple[str, ast.expr, int]]:
    """Every assignment, anywhere in the module, to NAME, obj.name or obj["NAME"]."""
    wanted = {n.lower() for n in names}
    found: list[tuple[str, ast.expr, int]] = []
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        if value is None:
            continue
        for target in targets:
            name = None
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            elif isinstance(target, ast.Subscript):
                key = literal(target.slice)
                name = key if isinstance(key, str) else None
            if name and name.lower() in wanted:
                found.append((name, value, node.lineno))
    return found


def string_literals(node: ast.expr) -> list[str]:
    """String constants a value can evaluate to: the string itself or an ``x or "default"`` tail."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        return [s for value in node.values for s in string_literals(value)]
    return []
