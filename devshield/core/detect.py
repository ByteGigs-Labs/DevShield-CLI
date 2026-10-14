from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from devshield.core.models import Confidence, DetectedFramework, Framework

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
    _docker,
    _github_actions,
)


def detect_frameworks(ctx: ProjectContext) -> tuple[DetectedFramework, ...]:
    return tuple(found for detector in DETECTORS if (found := detector(ctx)) is not None)
