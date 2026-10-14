from devshield.testing import run_rule
from devshield_plugin_example import SecurityTodo


def test_flags_a_security_todo(tmp_path):
    findings = run_rule(
        SecurityTodo, tmp_path, {"src/app.js": "const a = 1;\n// TODO(security): validate input\n"}
    )
    assert [(f.rule_id, f.location.file, f.location.line) for f in findings] == [
        ("EX001", "src/app.js", 2)
    ]


def test_ignores_ordinary_todos(tmp_path):
    assert run_rule(SecurityTodo, tmp_path, {"src/app.js": "// TODO: rename this\n"}) == []
