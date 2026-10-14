from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from devshield.core.models import Category, Finding, Severity
from devshield.core.secrets import find_secrets, mask

IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")
SECRET_KEY = re.compile(r"SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL", re.I)
BENIGN_VALUE = re.compile(r"^(?:|/\S*|true|false|\d+|https?://\S+|\$\{?\w+\}?)$", re.I)
LARGE_IMAGE_BYTES = 1024**3
MANY_LAYERS = 40
STALE_DAYS = 180
RISKY_PORTS = {
    22: ("SSH", Severity.HIGH),
    23: ("Telnet", Severity.HIGH),
    2375: ("unencrypted Docker API", Severity.CRITICAL),
    3306: ("MySQL", Severity.MEDIUM),
    5432: ("PostgreSQL", Severity.MEDIUM),
    6379: ("Redis", Severity.MEDIUM),
    9200: ("Elasticsearch", Severity.MEDIUM),
    11211: ("Memcached", Severity.MEDIUM),
    27017: ("MongoDB", Severity.MEDIUM),
}
ROOT_USERS = frozenset({"", "root", "0"})
TIMEOUT_SECONDS = 60

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


class DockerError(Exception):
    """Docker is missing, not running, or cannot find the image."""


@dataclass(frozen=True)
class ImageInfo:
    reference: str
    id: str
    size_bytes: int
    layers: int
    user: str
    ports: tuple[str, ...]
    env: tuple[str, ...]
    created: datetime | None
    history: tuple[str, ...] = ()
    architecture: str = ""


@dataclass
class ImageReport:
    image: ImageInfo
    findings: list[Finding] = field(default_factory=list)
    age_days: int | None = None


def default_runner(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed executable, arguments are validated
        ["docker", *args],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT_SECONDS,
        check=False,
    )


def _docker(runner: Runner, *args: str) -> str:
    try:
        done = runner(args)
    except FileNotFoundError as exc:
        raise DockerError("Docker was not found. Install Docker to scan images.") from exc
    except subprocess.TimeoutExpired as exc:
        raise DockerError("Docker did not answer in time.") from exc
    if done.returncode != 0:
        message = (done.stderr or "").strip()
        first = message.splitlines()[0] if message else "docker failed"
        lowered = message.lower()
        if "no such image" in lowered or "no such object" in lowered:
            raise DockerError(
                f"{args[-1]} was not found locally. Pull it first with `docker pull`."
            )
        if any(t in lowered for t in ("cannot connect", "daemon running", "permission denied")):
            raise DockerError(f"Docker is installed but not usable: {first}")
        raise DockerError(first)
    return done.stdout


def _parse_created(value: object) -> datetime | None:
    """Docker prints RFC 3339 with up to nine fractional digits and a UTC offset."""
    if not isinstance(value, str):
        return None
    cleaned = re.sub(r"\.\d+", "", value)
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def inspect_image(
    reference: str,
    runner: Runner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
) -> ImageInfo:
    if not IMAGE_REFERENCE.match(reference):
        raise DockerError(f"{reference!r} is not a valid image reference")
    if runner is default_runner and which("docker") is None:
        raise DockerError("Docker was not found. Install Docker to scan images.")
    try:
        documents = json.loads(_docker(runner, "image", "inspect", reference))
    except ValueError as exc:
        raise DockerError("docker image inspect returned unexpected output") from exc
    if not isinstance(documents, list) or not documents or not isinstance(documents[0], dict):
        raise DockerError(f"Image {reference} not found locally. Pull it first with `docker pull`.")
    document = documents[0]
    config = document.get("Config") or {}
    rootfs = document.get("RootFS") or {}
    history: list[str] = []
    try:
        for line in _docker(
            runner, "history", "--no-trunc", "--format", "{{json .}}", reference
        ).splitlines():
            entry = json.loads(line)
            if isinstance(entry, dict) and entry.get("CreatedBy"):
                history.append(str(entry["CreatedBy"]))
    except (DockerError, ValueError):
        history = []
    return ImageInfo(
        reference=reference,
        id=str(document.get("Id", ""))[:19],
        size_bytes=int(document.get("Size") or 0),
        layers=len(rootfs.get("Layers") or []),
        user=str(config.get("User") or ""),
        ports=tuple(sorted((config.get("ExposedPorts") or {}), key=_port_key)),
        env=tuple(str(e) for e in config.get("Env") or []),
        created=_parse_created(document.get("Created")),
        history=tuple(history),
        architecture=str(document.get("Architecture") or ""),
    )


def _port_key(port: str) -> tuple[int, str]:
    number = port.partition("/")[0]
    return (int(number) if number.isdigit() else 0, port)


def _finding(
    rule_id: str, title: str, severity: Severity, message: str, remediation: str
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=Category.DOCKER,
        message=message,
        remediation=remediation,
    )


def _env_secrets(info: ImageInfo) -> list[Finding]:
    findings: list[Finding] = []
    for entry in info.env:
        key, _, value = entry.partition("=")
        matches = list(find_secrets(entry))
        if matches:
            worst = max(matches, key=lambda m: m.severity)
            findings.append(
                _finding(
                    "IMG002",
                    "Secret baked into the image environment",
                    worst.severity,
                    f"ENV {key} holds a {worst.name.lower()}: {mask(worst.value)}",
                    "Pass secrets at runtime (secrets manager, --env-file) instead of ENV.",
                )
            )
        elif SECRET_KEY.search(key) and not BENIGN_VALUE.match(value):
            findings.append(
                _finding(
                    "IMG002",
                    "Secret baked into the image environment",
                    Severity.HIGH,
                    f"ENV {key} looks like a secret and has a value",
                    "Pass secrets at runtime (secrets manager, --env-file) instead of ENV.",
                )
            )
    for command in info.history:
        if any(True for _ in find_secrets(command)):
            findings.append(
                _finding(
                    "IMG002",
                    "Secret baked into the image environment",
                    Severity.HIGH,
                    "A secret appears in the image build history",
                    "Rebuild without putting secrets in ARG, ENV or RUN; use BuildKit secrets.",
                )
            )
            break
    return list(dict.fromkeys(findings))


def analyze_image(info: ImageInfo, now: datetime | None = None) -> ImageReport:
    now = now or datetime.now(UTC)
    findings: list[Finding] = []
    if info.user.split(":")[0] in ROOT_USERS:
        findings.append(
            _finding(
                "IMG001",
                "Image runs as root",
                Severity.MEDIUM,
                "The image has no non-root USER, so containers start as root",
                "Add a USER instruction with an unprivileged account.",
            )
        )
    findings += _env_secrets(info)
    for port in info.ports:
        number = port.partition("/")[0]
        if number.isdigit() and int(number) in RISKY_PORTS:
            label, severity = RISKY_PORTS[int(number)]
            findings.append(
                _finding(
                    "IMG003",
                    "Sensitive port exposed",
                    severity,
                    f"Port {port} ({label}) is exposed",
                    "Do not EXPOSE management or database ports in an application image.",
                )
            )
    if info.size_bytes > LARGE_IMAGE_BYTES:
        findings.append(
            _finding(
                "IMG004",
                "Large image",
                Severity.LOW,
                f"The image is {info.size_bytes / 1024**3:.1f} GiB",
                "Use a slim base image and a multi-stage build.",
            )
        )
    if info.layers > MANY_LAYERS:
        findings.append(
            _finding(
                "IMG005",
                "Many layers",
                Severity.LOW,
                f"The image has {info.layers} layers",
                "Combine RUN steps and use a multi-stage build.",
            )
        )
    age = max((now - info.created).days, 0) if info.created else None
    if age is not None and age > STALE_DAYS:
        findings.append(
            _finding(
                "IMG006",
                "Image not rebuilt recently",
                Severity.MEDIUM,
                f"Built {age} days ago, so its base layers likely lack security fixes",
                "Rebuild from a fresh base image regularly.",
            )
        )
    order = sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id, f.message))
    return ImageReport(info, order, age)


def scan_image(
    reference: str,
    runner: Runner = default_runner,
    now: datetime | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> ImageReport:
    return analyze_image(inspect_image(reference, runner, which), now)
