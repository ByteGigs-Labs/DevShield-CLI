from __future__ import annotations

import json

import pytest
from devshield.core.context import ProjectContext, is_test_path
from devshield.core.models import Confidence, Framework
from devshield.core.parsers import (
    flatten_json,
    flatten_yaml,
    load_template,
    module_assignments,
    parse_hcl,
    parse_module,
    parse_pipfile,
    parse_properties,
    parse_pyproject,
    parse_requirements_txt,
    secret_assignments,
    string_literals,
)

from tests.conftest import MakeProject


def detected(root: object) -> dict[Framework, Confidence]:
    return {d.framework: d.confidence for d in ProjectContext(root).frameworks}  # type: ignore[arg-type]


class TestDetection:
    def test_django_by_dependency_and_manage_py(self, make_project: MakeProject) -> None:
        root = make_project(
            {"requirements.txt": "Django>=5\n", "manage.py": "DJANGO_SETTINGS_MODULE = 'x'\n"}
        )
        assert detected(root) == {Framework.DJANGO: Confidence.HIGH}

    def test_django_with_one_signal_is_medium(self, make_project: MakeProject) -> None:
        assert detected(
            make_project({"pyproject.toml": '[project]\ndependencies = ["django"]\n'})
        ) == {Framework.DJANGO: Confidence.MEDIUM}

    def test_fastapi_and_flask_by_dependency_or_import(self, make_project: MakeProject) -> None:
        root = make_project(
            {"requirements.txt": "fastapi\nflask\n", "app.py": "from flask import Flask\n"}
        )
        found = detected(root)
        assert found[Framework.FASTAPI] is Confidence.MEDIUM
        assert found[Framework.FLASK] is Confidence.HIGH

    def test_python_import_alone_is_enough(self, make_project: MakeProject) -> None:
        assert Framework.FASTAPI in detected(make_project({"main.py": "import fastapi\n"}))

    def test_comments_and_strings_do_not_count(self, make_project: MakeProject) -> None:
        root = make_project({"a.py": "# from flask import Flask\nx = 'import flask'\n"})
        assert detected(root) == {}

    def test_nestjs(self, make_project: MakeProject) -> None:
        root = make_project({"package.json": '{"dependencies": {"@nestjs/core": "10"}}'})
        assert set(detected(root)) == {Framework.NODE, Framework.NESTJS}

    @pytest.mark.parametrize(
        "files",
        [
            {"pom.xml": "<artifactId>spring-boot-starter-parent</artifactId>"},
            {"build.gradle": "plugins { id 'org.springframework.boot' version '3.2.0' }"},
            {
                "build.gradle.kts": 'implementation("org.springframework.boot:spring-boot-starter-web")'
            },
        ],
    )
    def test_spring_boot(self, make_project: MakeProject, files: dict[str, str]) -> None:
        assert Framework.SPRING in detected(make_project(files))

    def test_plain_maven_project_is_not_spring(self, make_project: MakeProject) -> None:
        assert detected(make_project({"pom.xml": "<project></project>"})) == {}

    def test_aspnet_core(self, make_project: MakeProject) -> None:
        sdk = make_project({"A.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web"/>'})
        assert Framework.ASPNET in detected(sdk)

    def test_console_dotnet_project_is_not_aspnet(self, make_project: MakeProject) -> None:
        assert detected(make_project({"A.csproj": '<Project Sdk="Microsoft.NET.Sdk"/>'})) == {}

    def test_terraform_and_cloudformation(self, make_project: MakeProject) -> None:
        root = make_project(
            {
                "infra/main.tf": 'resource "aws_s3_bucket" "b" {}\n',
                "stack.yml": "Resources:\n  B:\n    Type: AWS::S3::Bucket\n",
                "other.json": '{"Resources": 1}',
                "package-lock.json": '{"Resources": "AWS::"}',
            }
        )
        found = detected(root)
        assert set(found) == {Framework.TERRAFORM, Framework.CLOUDFORMATION}
        assert ProjectContext(root).cloudformation_files == ["stack.yml"]

    def test_workflow_files_are_not_cloudformation(self, make_project: MakeProject) -> None:
        root = make_project(
            {".github/workflows/ci.yml": "name: x\njobs:\n  a:\n    steps: [Resources AWS::S3]\n"}
        )
        assert Framework.CLOUDFORMATION not in detected(root)

    def test_build_output_is_skipped_only_next_to_its_project_file(
        self, make_project: MakeProject
    ) -> None:
        root = make_project(
            {
                "pom.xml": "<project/>",
                "target/classes/application.properties": "x=1\n",
                "App.csproj": "<Project/>",
                "obj/Debug/Gen.cs": "class A {}\n",
                "bin/Debug/App.cs": "class B {}\n",
                ".terraform/modules/m/main.tf": 'resource "a" "b" {}\n',
            }
        )
        assert ProjectContext(root).files == ("App.csproj", "pom.xml")

    def test_folders_that_only_share_a_name_are_still_scanned(
        self, make_project: MakeProject
    ) -> None:
        root = make_project(
            {"app.py": "x = 1\n", "target/goals.py": "y = 2\n", "bin/run.sh": "echo\n"}
        )
        assert ProjectContext(root).files == ("app.py", "bin/run.sh", "target/goals.py")


def test_test_paths_for_the_new_ecosystems() -> None:
    for path in (
        "tests/test_a.py",
        "conftest.py",
        "src/test/java/com/A.java",
        "src/main/java/AServiceTest.java",
        "App.Tests/Calc.cs",
        "CalcTests.cs",
    ):
        assert is_test_path(path), path
    for path in ("src/main/java/Service.java", "App/Calc.cs", "app/models.py"):
        assert not is_test_path(path), path


class TestParsers:
    def test_requirements_txt(self) -> None:
        text = (
            "# comment\n-r base.txt\nDjango[argon2]>=5.0 ; python_version > '3.9'\n"
            "flask_cors==4.0  # inline\n-e .\ngit+https://x/y.git\n"
        )
        assert parse_requirements_txt(text) == {"django": ">=5.0", "flask-cors": "==4.0"}

    def test_pyproject_formats(self) -> None:
        pep621 = (
            '[project]\ndependencies = ["FastAPI>=0.1", "uvicorn"]\n'
            '[project.optional-dependencies]\ndev = ["pytest"]\n'
        )
        poetry = '[tool.poetry.dependencies]\npython = "^3.11"\nFlask = "^3"\n[tool.poetry.group.dev.dependencies]\nblack = "*"\n'
        assert set(parse_pyproject(pep621)) == {"fastapi", "uvicorn", "pytest"}
        assert set(parse_pyproject(poetry)) == {"flask", "black"}
        assert parse_pyproject("not [toml") == {}

    def test_pipfile(self) -> None:
        assert set(parse_pipfile('[packages]\nDjango = "*"\n[dev-packages]\npytest = "*"\n')) == {
            "django",
            "pytest",
        }

    def test_properties(self) -> None:
        text = "# c\n! c\na.b=1\nc.d : two words\n\ne = \nbad line\n"
        assert [(e.key, e.value, e.line) for e in parse_properties(text)] == [
            ("a.b", "1", 3),
            ("c.d", "two words", 4),
            ("e", "", 6),
        ]

    def test_yaml_is_flattened_with_lines_across_documents(self) -> None:
        text = "a:\n  b: 1\n  c:\n    - x\n    - y\n---\nd: 2\n"
        assert [(e.key, e.value, e.line) for e in flatten_yaml(text)] == [
            ("a.b", "1", 2),
            ("a.c[0]", "x", 4),
            ("a.c[1]", "y", 5),
            ("d", "2", 7),
        ]
        assert flatten_yaml("a: [") == []

    def test_json_is_flattened_with_lines(self) -> None:
        text = json.dumps({"A": {"B": "x", "C": True}, "D": [1]}, indent=2)
        assert [(e.key, e.value, e.line) for e in flatten_json(text)] == [
            ("A:B", "x", 3),
            ("A:C", "true", 4),
            ("D:0", "1", 7),
        ]
        assert flatten_json("{") == []

    def test_hcl_blocks_attributes_and_nested_blocks(self) -> None:
        text = (
            '# top\nresource "aws_s3_bucket" "b" {\n  bucket = "x" # trailing\n'
            '  tags = {\n    a = "b"\n  }\n  versioning {\n    enabled = true\n  }\n'
            '  policy = <<EOT\n{"a": "}"}\nEOT\n  list = [\n    "one",\n    "two",\n  ]\n}\n'
            'resource "aws_db_instance" "d" { storage_encrypted = false }\n'
            'data "aws_iam_policy_document" "p" {\n  statement {\n    effect = "Allow"\n  }\n}\n'
        )
        first, second, third = parse_hcl(text)
        assert (first.kind, first.labels, first.line) == ("resource", ("aws_s3_bucket", "b"), 2)
        assert first.value("bucket") == '"x"' and first.line_of("bucket") == 3
        assert first.value("tags") == '{\na = "b"\n}'
        assert first.children("versioning")[0].value("enabled") == "true"
        assert '{"a": "}"}' in (first.value("policy") or "")
        assert first.value("list") == '[\n"one",\n"two",\n]'
        assert second.value("storage_encrypted") == "false"
        assert third.kind == "data" and third.children("statement")[0].value("effect") == '"Allow"'
        assert parse_hcl("nothing here") == []

    def test_cloudformation_tags_load(self) -> None:
        template = load_template(
            "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n"
            "      Name: !Sub 'x-${A}'\n      Arn: !GetAtt [B, Arn]\n      Ref: !Ref A\n"
        )
        assert template is not None
        assert template["Resources"]["B"]["Properties"]["Arn"] == ["B", "Arn"]
        assert load_template('{"Resources": {}}', is_json=True) == {"Resources": {}}
        assert load_template("- a\n- b") is None and load_template("a: [") is None

    def test_python_ast_helpers(self) -> None:
        tree = parse_module(
            "A = 1\nB: str = 'x'\nA = 2\nclass C:\n    SECRET_KEY = os.environ.get('K') or 'fallback'\n"
            "app.secret_key = 'dev'\napp.config['SECRET_KEY'] = 'z'\nSECRET_KEY = os.environ['K']\n"
        )
        assert tree is not None
        assigned = module_assignments(tree)
        assert assigned["A"][1] == 3 and assigned["B"][1] == 2
        found = secret_assignments(tree, frozenset({"SECRET_KEY", "secret_key"}))
        literals = {line: string_literals(value) for _, value, line in found}
        assert literals == {5: ["fallback"], 6: ["dev"], 7: ["z"], 8: []}
        assert parse_module("def (") is None


class TestHclValues:
    def test_literals_lists_objects_and_jsonencode(self) -> None:
        from devshield.core.parsers import Call, Opaque, parse_hcl_value

        value = parse_hcl_value(
            'jsonencode({\n  a = "x"\n  "b" : [1, 2.5, true, null]\n  c = { d = var.y }\n'
            "  e = merge(local.a, local.b)\n  f = cond ? 1 : 2\n})"
        )
        assert value == {
            "a": "x",
            "b": [1, 2.5, True, None],
            "c": {"d": Opaque("var.y")},
            "e": Call("merge", (Opaque("local.a"), Opaque("local.b"))),
            "f": Opaque("cond ? 1 : 2"),
        }

    def test_heredoc_json_and_garbage(self) -> None:
        from devshield.core.parsers import Opaque, parse_hcl_value

        assert parse_hcl_value('<<-EOT\n  {"a": [1]}\n  EOT') == {"a": [1]}
        assert parse_hcl_value("<<EOT\nnot json\nEOT") == Opaque("heredoc")
        assert parse_hcl_value("") == Opaque("")
        assert parse_hcl_value("{ a = ") == {"a": Opaque("")}


def test_locals_and_variable_blocks_are_parsed() -> None:
    blocks = parse_hcl(
        'locals {\n  a = "x"\n  b = [1]\n}\nvariable "v" {\n  type = string\n  default = "d"\n}\n'
    )
    assert [(b.kind, b.labels) for b in blocks] == [("locals", ()), ("variable", ("v",))]
    assert blocks[0].value("b") == "[1]" and blocks[1].value("default") == '"d"'
