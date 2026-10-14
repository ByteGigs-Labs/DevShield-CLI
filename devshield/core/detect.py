from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

from devshield.core.models import Confidence, DetectedFramework, Framework
from devshield.core.search import search

if TYPE_CHECKING:
    from devshield.core.context import ProjectContext

Detector = Callable[["ProjectContext"], DetectedFramework | None]


def _detected(
    framework: Framework, evidence: list[str], high_at: int = 1
) -> DetectedFramework | None:
    if not evidence:
        return None
    confidence = Confidence.HIGH if len(evidence) >= high_at else Confidence.MEDIUM
    return DetectedFramework(framework=framework, confidence=confidence, evidence=tuple(evidence))


def _node_package(framework: Framework, package: str) -> Detector:
    def detect(ctx: ProjectContext) -> DetectedFramework | None:
        evidence = (
            [f"package.json depends on {package}"] if package in ctx.node_dependencies else []
        )
        return _detected(framework, evidence)

    return detect


def _laravel(ctx: ProjectContext) -> DetectedFramework | None:
    evidence = []
    if ctx.exists("artisan"):
        evidence.append("artisan")
    if "laravel/framework" in ctx.composer_dependencies:
        evidence.append("composer.json requires laravel/framework")
    return _detected(Framework.LARAVEL, evidence, high_at=2)


def _node(ctx: ProjectContext) -> DetectedFramework | None:
    return _detected(Framework.NODE, ["package.json"] if ctx.exists("package.json") else [])


def _python_framework(framework: Framework, package: str, imports: str) -> Detector:
    pattern = re.compile(rf"^\s*(?:from|import)\s+{imports}\b")

    def detect(ctx: ProjectContext) -> DetectedFramework | None:
        evidence = []
        if package in ctx.python_dependencies:
            evidence.append(f"Python dependency {package}")
        hit = next(search(ctx, ctx.python_files, pattern), None)
        if hit:
            evidence.append(f"{hit.file} imports {imports}")
        return _detected(framework, evidence, high_at=2)

    return detect


def _django(ctx: ProjectContext) -> DetectedFramework | None:
    evidence = []
    if "django" in ctx.python_dependencies:
        evidence.append("Python dependency django")
    if "DJANGO_SETTINGS_MODULE" in (ctx.read_text("manage.py") or ""):
        evidence.append("manage.py")
    return _detected(Framework.DJANGO, evidence, high_at=2)


def _spring(ctx: ProjectContext) -> DetectedFramework | None:
    evidence = []
    if "spring-boot" in (ctx.read_text("pom.xml") or ""):
        evidence.append("pom.xml uses spring-boot")
    for gradle in ("build.gradle", "build.gradle.kts"):
        text = ctx.read_text(gradle) or ""
        if "org.springframework.boot" in text or "spring-boot-starter" in text:
            evidence.append(f"{gradle} uses Spring Boot")
    return _detected(Framework.SPRING, evidence)


def _aspnet(ctx: ProjectContext) -> DetectedFramework | None:
    evidence = [
        f
        for f in ctx.match("*.csproj")
        if "Microsoft.NET.Sdk.Web" in (ctx.read_text(f) or "")
        or "Microsoft.AspNetCore" in (ctx.read_text(f) or "")
    ]
    return _detected(Framework.ASPNET, evidence)


def _terraform(ctx: ProjectContext) -> DetectedFramework | None:
    return _detected(Framework.TERRAFORM, ctx.terraform_files[:3])


def _cloudformation(ctx: ProjectContext) -> DetectedFramework | None:
    return _detected(Framework.CLOUDFORMATION, ctx.cloudformation_files[:3])


def _docker(ctx: ProjectContext) -> DetectedFramework | None:
    return _detected(Framework.DOCKER, [*ctx.dockerfiles, *ctx.compose_files])


def _github_actions(ctx: ProjectContext) -> DetectedFramework | None:
    return _detected(Framework.GITHUB_ACTIONS, ctx.workflow_files)


DETECTORS: tuple[Detector, ...] = (
    _laravel,
    _node,
    _node_package(Framework.EXPRESS, "express"),
    _node_package(Framework.REACT, "react"),
    _node_package(Framework.NEXTJS, "next"),
    _node_package(Framework.NESTJS, "@nestjs/core"),
    _django,
    _python_framework(Framework.FASTAPI, "fastapi", "fastapi"),
    _python_framework(Framework.FLASK, "flask", "flask"),
    _spring,
    _aspnet,
    _terraform,
    _cloudformation,
    _docker,
    _github_actions,
)


def detect_frameworks(ctx: ProjectContext) -> tuple[DetectedFramework, ...]:
    return tuple(found for detector in DETECTORS if (found := detector(ctx)) is not None)
