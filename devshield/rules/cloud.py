"""Rules for AWS infrastructure as code: Terraform (.tf) and CloudFormation templates."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, ClassVar

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.parsers import HclBlock
from devshield.core.rule import Rule

IAC = frozenset({Framework.TERRAFORM, Framework.CLOUDFORMATION})
PUBLIC_ACLS = frozenset({"public-read", "public-read-write", "authenticated-read"})
PUBLIC_CFN_ACLS = frozenset({"PublicRead", "PublicReadWrite", "AuthenticatedRead"})
BLOCK_SETTINGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)
CFN_BLOCK_SETTINGS = (
    "BlockPublicAcls",
    "BlockPublicPolicy",
    "IgnorePublicAcls",
    "RestrictPublicBuckets",
)
ADMIN_PORTS = (22, 3389)
DATABASE_PORTS = (1433, 3306, 5432, 6379, 9200, 11211, 27017)
OPEN_CIDRS = ("0.0.0.0/0", "::/0")
WILDCARD = r"""(?:"\*"|\[[^\]]*"\*"[^\]]*\])"""
POLICY_ACTION = re.compile(rf"""["']?Action["']?\s*[:=]\s*{WILDCARD}""")
POLICY_RESOURCE = re.compile(rf"""["']?Resource["']?\s*[:=]\s*{WILDCARD}""")
PUBLIC_PRINCIPAL = re.compile(
    r"""["']?Principal["']?\s*[:=]\s*(?:["']\*["']|\{\s*["']?AWS["']?\s*[:=]\s*["']\*["']\s*\})"""
)
IAM_POLICY_TYPES = frozenset(
    {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
)


@dataclass(frozen=True)
class Spot:
    file: str
    line: int


def unquote(value: str | None) -> str:
    return (value or "").strip().strip('"').strip("'")


def as_bool(value: Any) -> bool | None:
    text = str(value).strip().strip('"').lower() if value is not None else ""
    return True if text == "true" else False if text == "false" else None


def terraform_blocks(ctx: ProjectContext) -> Iterator[tuple[str, HclBlock]]:
    for file in ctx.terraform_files:
        for block in ctx.terraform(file):
            if block.kind in {"resource", "data"}:
                yield file, block


def cfn_resources(ctx: ProjectContext) -> Iterator[tuple[str, str, str, dict[str, Any]]]:
    """(file, logical id, resource type, properties) for each CloudFormation resource."""
    for file in ctx.cloudformation_files:
        template = ctx.template(file)
        resources = template.get("Resources") if template else None
        for logical_id, body in (resources if isinstance(resources, dict) else {}).items():
            if isinstance(body, dict) and isinstance(body.get("Type"), str):
                props = body.get("Properties")
                yield file, str(logical_id), body["Type"], props if isinstance(props, dict) else {}


def cfn_line(ctx: ProjectContext, file: str, logical_id: str, *path: str) -> int:
    for depth in range(len(path), -1, -1):
        line = ctx.line_of(
            file, "Resources", logical_id, *(["Properties", *path[:depth]] if depth else [])
        )
        if line:
            return line
    return 1


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def cfn_statements(document: Any) -> Iterator[dict[str, Any]]:
    statements = document.get("Statement") if isinstance(document, dict) else None
    for statement in _as_list(statements) if statements else []:
        if isinstance(statement, dict):
            yield statement


def _has_star(value: Any) -> bool:
    return any(item == "*" for item in _as_list(value))


class PublicBucket(Rule):
    id = "SH401"
    title = "S3 bucket is publicly accessible"
    severity = Severity.HIGH
    category = Category.SECURITY
    applies_to = IAC
    description = (
        "A public S3 bucket lets anyone on the internet read, and sometimes write, its objects. "
        "Public buckets are a leading cause of data leaks."
    )
    remediation = (
        "Use a private ACL, enable all four settings of the public access block, and grant "
        "access with specific principals or CloudFront origin access control."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, block in terraform_blocks(ctx):
            if block.kind != "resource":
                continue
            kind = block.type
            if (
                kind in {"aws_s3_bucket", "aws_s3_bucket_acl"}
                and unquote(block.value("acl")) in PUBLIC_ACLS
            ):
                yield self.finding(
                    f"{block.labels[-1]} uses the {unquote(block.value('acl'))} ACL",
                    file=file,
                    line=block.line_of("acl"),
                )
            elif kind == "aws_s3_bucket_public_access_block":
                for setting in BLOCK_SETTINGS:
                    if as_bool(block.value(setting)) is False:
                        yield self.finding(
                            f"Public access block sets {setting} = false",
                            file=file,
                            line=block.line_of(setting),
                        )
            elif kind == "aws_s3_bucket_policy" and self._public_policy(
                block.value("policy") or ""
            ):
                yield self.finding(
                    "Bucket policy allows every principal",
                    file=file,
                    line=block.line_of("policy"),
                )
        for file, logical_id, kind, props in cfn_resources(ctx):
            if kind == "AWS::S3::Bucket":
                acl = props.get("AccessControl")
                if acl in PUBLIC_CFN_ACLS:
                    yield self.finding(
                        f"{logical_id} uses the {acl} access control",
                        file=file,
                        line=cfn_line(ctx, file, logical_id, "AccessControl"),
                    )
                access_block = props.get("PublicAccessBlockConfiguration")
                for setting in CFN_BLOCK_SETTINGS:
                    if (
                        isinstance(access_block, dict)
                        and as_bool(access_block.get(setting)) is False
                    ):
                        yield self.finding(
                            f"Public access block sets {setting} to false",
                            file=file,
                            line=cfn_line(
                                ctx, file, logical_id, "PublicAccessBlockConfiguration", setting
                            ),
                        )
            elif kind == "AWS::S3::BucketPolicy":
                for statement in cfn_statements(props.get("PolicyDocument")):
                    principal = statement.get("Principal")
                    everyone = principal == "*" or (
                        isinstance(principal, dict) and _has_star(principal.get("AWS"))
                    )
                    if (
                        statement.get("Effect") == "Allow"
                        and everyone
                        and "Condition" not in statement
                    ):
                        yield self.finding(
                            f"{logical_id} policy allows every principal",
                            file=file,
                            line=cfn_line(ctx, file, logical_id, "PolicyDocument"),
                        )

    @staticmethod
    def _public_policy(text: str) -> bool:
        return (
            PUBLIC_PRINCIPAL.search(text) is not None
            and "Allow" in text
            and "Condition" not in text
            and "Deny" not in text
        )


class WildcardIamPolicy(Rule):
    id = "SH402"
    title = "IAM policy grants wildcard permissions"
    severity = Severity.HIGH
    category = Category.SECURITY
    applies_to = IAC
    description = (
        "An Allow statement with Action '*' grants every API action, and with Resource '*' as "
        "well it is full administrator access. A leaked credential then controls the account."
    )
    remediation = "List the specific actions and resources the workload needs (least privilege)."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, block in terraform_blocks(ctx):
            if block.kind == "resource" and block.type in IAM_POLICY_TYPES:
                text = block.value("policy") or ""
                if "Deny" in text:
                    continue
                if POLICY_ACTION.search(text):
                    yield self._wildcard(
                        file, block.line_of("policy"), bool(POLICY_RESOURCE.search(text))
                    )
            elif block.kind == "data" and block.type == "aws_iam_policy_document":
                for item in block.children("statement"):
                    effect = unquote(item.value("effect")) or "Allow"
                    actions = item.value("actions") or ""
                    resources = item.value("resources") or ""
                    if effect == "Allow" and re.search(r'"\*"', actions):
                        yield self._wildcard(file, item.line, bool(re.search(r'"\*"', resources)))
        for file, logical_id, kind, props in cfn_resources(ctx):
            documents: list[Any] = []
            if kind in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}:
                documents.append(props.get("PolicyDocument"))
            elif kind in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}:
                for policy in _as_list(props.get("Policies") or []):
                    documents.append(
                        policy.get("PolicyDocument") if isinstance(policy, dict) else None
                    )
            for document in documents:
                for statement in cfn_statements(document):
                    if statement.get("Effect") == "Allow" and _has_star(statement.get("Action")):
                        yield self._wildcard(
                            file,
                            cfn_line(ctx, file, logical_id),
                            _has_star(statement.get("Resource")),
                        )

    def _wildcard(self, file: str, line: int, resource_star: bool) -> Finding:
        return self.finding(
            "Allows every action on every resource" if resource_star else "Allows every action",
            file=file,
            line=line,
            severity=Severity.CRITICAL if resource_star else None,
        )


def _port(value: Any) -> int | None:
    text = str(value).strip().strip('"') if value is not None else ""
    return int(text) if text.lstrip("-").isdigit() else None


def _exposure(low: int | None, high: int | None, protocol: str) -> tuple[Severity, str] | None:
    if protocol in {"-1", "all"}:
        return Severity.HIGH, "all ports"
    if low is None or high is None:
        return None
    if low <= 0 and high >= 65535:
        return Severity.HIGH, "all ports"
    for port in ADMIN_PORTS:
        if low <= port <= high:
            return Severity.HIGH, f"port {port}"
    for port in DATABASE_PORTS:
        if low <= port <= high:
            return Severity.MEDIUM, f"database port {port}"
    return None


class OpenSecurityGroup(Rule):
    id = "SH403"
    title = "Security group open to the internet"
    severity = Severity.HIGH
    category = Category.SECURITY
    applies_to = IAC
    description = (
        "Ingress from 0.0.0.0/0 to SSH, RDP, databases or every port exposes those services "
        "to constant scanning and brute-force attempts."
    )
    remediation = (
        "Restrict the source to your own CIDR range or a security group, and use SSM Session "
        "Manager or a VPN instead of public SSH."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, block in terraform_blocks(ctx):
            if block.kind != "resource":
                continue
            if block.type == "aws_security_group":
                for ingress in block.children("ingress"):
                    yield from self._tf(
                        file, ingress, "cidr_blocks", "ipv6_cidr_blocks", "protocol"
                    )
            elif (
                block.type == "aws_security_group_rule"
                and unquote(block.value("type")) == "ingress"
            ):
                yield from self._tf(file, block, "cidr_blocks", "ipv6_cidr_blocks", "protocol")
            elif block.type == "aws_vpc_security_group_ingress_rule":
                yield from self._tf(file, block, "cidr_ipv4", "cidr_ipv6", "ip_protocol")
        for file, logical_id, kind, props in cfn_resources(ctx):
            rules: list[Any] = []
            if kind == "AWS::EC2::SecurityGroup":
                rules = _as_list(props.get("SecurityGroupIngress") or [])
            elif kind == "AWS::EC2::SecurityGroupIngress":
                rules = [props]
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                if not any(rule.get(k) in OPEN_CIDRS for k in ("CidrIp", "CidrIpv6")):
                    continue
                found = _exposure(
                    _port(rule.get("FromPort")),
                    _port(rule.get("ToPort")),
                    str(rule.get("IpProtocol", "")),
                )
                if found:
                    yield self.finding(
                        f"{logical_id} allows the internet to reach {found[1]}",
                        file=file,
                        line=cfn_line(ctx, file, logical_id),
                        severity=found[0],
                    )

    def _tf(
        self, file: str, block: HclBlock, ipv4: str, ipv6: str, protocol: str
    ) -> Iterator[Finding]:
        cidrs = (block.value(ipv4) or "") + (block.value(ipv6) or "")
        if not any(cidr in cidrs for cidr in OPEN_CIDRS):
            return
        found = _exposure(
            _port(block.value("from_port")),
            _port(block.value("to_port")),
            unquote(block.value(protocol)),
        )
        if found:
            yield self.finding(
                f"Ingress from the internet to {found[1]}",
                file=file,
                line=block.line,
                severity=found[0],
            )


class UnencryptedStorage(Rule):
    id = "SH404"
    title = "Storage encryption at rest not enabled"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    applies_to = IAC
    description = (
        "Unencrypted databases and volumes expose their data if a snapshot, a disk or a backup "
        "is copied or shared by mistake, and many compliance regimes require encryption."
    )
    remediation = (
        "Set storage_encrypted = true (RDS) or encrypted = true (EBS), ideally with a KMS key."
    )
    tf_attributes: ClassVar[dict[str, str]] = {
        "aws_db_instance": "storage_encrypted",
        "aws_rds_cluster": "storage_encrypted",
        "aws_ebs_volume": "encrypted",
    }
    cfn_attributes: ClassVar[dict[str, str]] = {
        "AWS::RDS::DBInstance": "StorageEncrypted",
        "AWS::RDS::DBCluster": "StorageEncrypted",
        "AWS::EC2::Volume": "Encrypted",
    }
    restored_from = ("snapshot_identifier", "replicate_source_db", "source_db_instance_identifier")
    cfn_restored_from = (
        "DBSnapshotIdentifier",
        "SourceDBInstanceIdentifier",
        "SnapshotIdentifier",
        "SourceDBClusterIdentifier",
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, block in terraform_blocks(ctx):
            attribute = self.tf_attributes.get(block.type) if block.kind == "resource" else None
            if attribute is None or any(block.value(a) for a in self.restored_from):
                continue
            if as_bool(block.value(attribute)) is not True and (
                block.value(attribute) is None or as_bool(block.value(attribute)) is False
            ):
                yield self.finding(
                    f"{block.labels[-1]} does not set {attribute} = true",
                    file=file,
                    line=block.line_of(attribute),
                )
        for file, logical_id, kind, props in cfn_resources(ctx):
            attribute = self.cfn_attributes.get(kind)
            if attribute is None or any(props.get(a) for a in self.cfn_restored_from):
                continue
            value = props.get(attribute)
            if value is None or as_bool(value) is False:
                yield self.finding(
                    f"{logical_id} does not set {attribute} to true",
                    file=file,
                    line=cfn_line(ctx, file, logical_id, attribute),
                )


class PubliclyAccessibleDatabase(Rule):
    id = "SH405"
    title = "Database reachable from the internet"
    severity = Severity.HIGH
    category = Category.SECURITY
    applies_to = IAC
    description = (
        "A database with a public address is exposed to the internet and to brute-force and "
        "exploit attempts, even when a security group limits who can connect."
    )
    remediation = (
        "Set publicly_accessible = false and reach the database through a private subnet, "
        "a VPN or a bastion host."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, block in terraform_blocks(ctx):
            if block.kind == "resource" and as_bool(block.value("publicly_accessible")) is True:
                yield self.finding(
                    f"{block.labels[-1]} has publicly_accessible = true",
                    file=file,
                    line=block.line_of("publicly_accessible"),
                )
        for file, logical_id, _kind, props in cfn_resources(ctx):
            if as_bool(props.get("PubliclyAccessible")) is True:
                yield self.finding(
                    f"{logical_id} has PubliclyAccessible: true",
                    file=file,
                    line=cfn_line(ctx, file, logical_id, "PubliclyAccessible"),
                )
