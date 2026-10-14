from __future__ import annotations

from typing import ClassVar

import pytest
from devshield.core.config import Config
from devshield.core.models import Severity
from devshield.core.runner import ScanOptions, run_scan

from tests.conftest import MakeProject
from tests.rules.helpers import REGISTRY, SPRING


def scan(root: object, *rules: str, config: Config | None = None):  # type: ignore[no-untyped-def]
    return run_scan(root, config or Config(), REGISTRY, ScanOptions(only=rules))  # type: ignore[arg-type]


def policy(statements: str) -> dict[str, str]:
    return {
        "main.tf": (
            'resource "aws_iam_policy" "p" {\n  policy = jsonencode({\n    Version = "2012-10-17"\n'
            f"    Statement = [\n{statements}\n    ]\n  }})\n}}\n"
        )
    }


class TestIamPolicyParsing:
    def test_statements_are_judged_one_by_one(self, make_project: MakeProject) -> None:
        # Two statements that each hold one wildcard must not be merged into "admin access".
        root = make_project(
            policy(
                '      { Effect = "Allow", Action = "*", Resource = "arn:aws:s3:::x" },\n'
                '      { Effect = "Allow", Action = "s3:GetObject", Resource = "*" }'
            )
        )
        [finding] = scan(root, "SH402").findings
        assert finding.severity is Severity.HIGH and finding.message == "Allows every action"

    def test_admin_statement_is_critical(self, make_project: MakeProject) -> None:
        root = make_project(
            policy('      { Effect = "Allow", Action = ["s3:Get*", "*"], Resource = ["*"] }')
        )
        [finding] = scan(root, "SH402").findings
        assert finding.severity is Severity.CRITICAL

    def test_deny_statements_and_references_are_not_flagged(
        self, make_project: MakeProject
    ) -> None:
        root = make_project(
            policy(
                '      { Effect = "Deny", Action = "*", Resource = "*" },\n'
                '      {\n        Effect = "Allow"\n        Action = var.actions\n'
                "        Resource = aws_s3_bucket.b.arn\n      }"
            )
        )
        assert scan(root, "SH402").findings == ()

    def test_heredoc_json_policies_are_read(self, make_project: MakeProject) -> None:
        root = make_project(
            {
                "main.tf": (
                    'resource "aws_iam_policy" "p" {\n  policy = <<EOF\n'
                    '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}\nEOF\n}\n'
                )
            }
        )
        assert [f.severity for f in scan(root, "SH402").findings] == [Severity.CRITICAL]

    def test_bucket_policy_conditions_and_principals(self, make_project: MakeProject) -> None:
        def bucket(statement: str) -> dict[str, str]:
            return {
                "main.tf": (
                    'resource "aws_s3_bucket_policy" "p" {\n  policy = jsonencode({\n'
                    f"    Statement = [{statement}]\n  }})\n}}\n"
                )
            }

        public = '{ Effect = "Allow", Principal = { AWS = "*" }, Action = "s3:GetObject" }'
        conditional = (
            '{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", '
            'Condition = { StringEquals = { "aws:SourceVpce" = "vpce-1" } } }'
        )
        assert len(scan(make_project(bucket(public)), "SH401").findings) == 1
        assert scan(make_project(bucket(conditional)), "SH401").findings == ()


class TestDevProfiles:
    FILES: ClassVar[dict[str, str]] = {
        **SPRING,
        "src/main/resources/application-dev.properties": "management.endpoints.web.exposure.include=*\n",
    }

    def test_dev_profile_files_are_skipped_by_default(self, make_project: MakeProject) -> None:
        assert scan(make_project(self.FILES), "SH018").findings == ()

    def test_scan_dev_files_turns_the_skip_off(self, make_project: MakeProject) -> None:
        found = scan(make_project(self.FILES), "SH018", config=Config(scan_dev_files=True))
        assert [f.rule_id for f in found.findings] == ["SH018"]

    def test_the_option_reaches_the_python_rules(self, make_project: MakeProject) -> None:
        files = {"requirements.txt": "Django\n", "web/settings/dev.py": "ALLOWED_HOSTS = ['*']\n"}
        root = make_project(files)
        assert scan(root, "SH014").findings == ()
        assert len(scan(root, "SH014", config=Config(scan_dev_files=True)).findings) == 1

    @pytest.mark.parametrize("value", ["true", "false"])
    def test_config_file_accepts_the_option(self, make_project: MakeProject, value: str) -> None:
        from devshield.core.config import load_config

        root = make_project({"devshield.yml": f"scan_dev_files: {value}\n"})
        assert load_config(root).scan_dev_files is (value == "true")
