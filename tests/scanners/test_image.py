from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import pytest
from devshield.cli import app as cli
from devshield.cli.app import app
from devshield.scanners import image as image_module
from devshield.scanners.image import DockerError, ImageInfo, analyze_image, scan_image
from typer.testing import CliRunner

NOW = datetime(2026, 10, 14, tzinfo=UTC)
GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def inspect_document(**config: Any) -> list[dict[str, Any]]:
    return [
        {
            "Id": "sha256:" + "a" * 64,
            "Created": "2026-09-01T10:00:00.123456789Z",
            "Size": 150_000_000,
            "Architecture": "amd64",
            "Config": {"User": "node", "Env": ["PATH=/usr/bin"], **config},
            "RootFS": {"Layers": ["l"] * 8},
        }
    ]


def fake_docker(
    document: object,
    history: Sequence[str] = ('CMD ["node"]',),
    returncode: int = 0,
    stderr: str = "",
) -> image_module.Runner:
    def run(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if returncode:
            return subprocess.CompletedProcess(args, returncode, "", stderr)
        if args[:2] == ("image", "inspect"):
            return subprocess.CompletedProcess(args, 0, json.dumps(document), "")
        lines = "\n".join(json.dumps({"CreatedBy": h, "Size": "0B"}) for h in history)
        return subprocess.CompletedProcess(args, 0, lines, "")

    return run


def ids(report: image_module.ImageReport) -> list[str]:
    return [f.rule_id for f in report.findings]


def info(**overrides: Any) -> ImageInfo:
    values: dict[str, Any] = {
        "reference": "app:1",
        "id": "sha256:abc",
        "size_bytes": 100,
        "layers": 3,
        "user": "app",
        "ports": (),
        "env": (),
        "created": NOW,
    }
    return ImageInfo(**{**values, **overrides})


def test_inspects_a_clean_image() -> None:
    report = scan_image("app:1", fake_docker(inspect_document()), NOW)
    assert report.findings == [] and report.age_days == 42
    assert (report.image.layers, report.image.size_bytes, report.image.user) == (
        8,
        150_000_000,
        "node",
    )


def test_every_check_fires() -> None:
    document = inspect_document(
        User="",
        ExposedPorts={"6379/tcp": {}, "22/tcp": {}, "8080/tcp": {}},
        Env=[
            "API_TOKEN=abc123def456ghi789",
            f"GITHUB={GITHUB_TOKEN}",
            "HOME=/root",
            "DEBUG_PASSWORD=",
        ],
    )
    document[0]["Size"] = 3 * 1024**3
    document[0]["Created"] = "2025-01-01T00:00:00Z"
    document[0]["RootFS"]["Layers"] = ["l"] * 60
    report = scan_image("app:1", fake_docker(document), NOW)
    assert ids(report).count("IMG002") == 2
    assert set(ids(report)) == {"IMG001", "IMG002", "IMG003", "IMG004", "IMG005", "IMG006"}
    assert report.image.ports == ("22/tcp", "6379/tcp", "8080/tcp")
    messages = " ".join(f.message for f in report.findings)
    assert GITHUB_TOKEN not in messages and "abc123def456ghi789" not in messages
    assert report.findings[0].severity >= report.findings[-1].severity


def test_root_user_forms() -> None:
    for user, flagged in (
        ("", True),
        ("root", True),
        ("0:0", True),
        ("1000", False),
        ("app:app", False),
    ):
        assert ("IMG001" in ids(analyze_image(info(user=user), NOW))) is flagged


def test_secret_in_build_history_is_reported_once() -> None:
    document = inspect_document()
    history = [f"ENV TOKEN={GITHUB_TOKEN}", f"RUN curl -H {GITHUB_TOKEN} x"]
    report = scan_image("app:1", fake_docker(document, history), NOW)
    assert ids(report) == ["IMG002"] and "build history" in report.findings[0].message


def test_placeholder_env_values_are_not_flagged() -> None:
    env = ("DB_PASSWORD=${DB_PASSWORD}", "API_KEY=", "SECRET_FILE=/run/secrets/x", "TOKEN_TTL=3600")
    assert ids(analyze_image(info(env=env), NOW)) == []


class TestFailures:
    def test_docker_missing(self) -> None:
        with pytest.raises(DockerError, match="not found"):
            scan_image("app:1", which=lambda _: None)

    def test_docker_binary_vanishes(self) -> None:
        def run(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError

        with pytest.raises(DockerError, match="Install Docker"):
            scan_image("app:1", run)

    def test_daemon_down(self) -> None:
        runner = fake_docker(
            None, returncode=1, stderr="Cannot connect to the Docker daemon at unix:///x"
        )
        with pytest.raises(DockerError, match="not usable"):
            scan_image("app:1", runner)

    def test_image_missing(self) -> None:
        runner = fake_docker(
            None, returncode=1, stderr="Error response from daemon: No such image: app:1"
        )
        with pytest.raises(DockerError, match="docker pull"):
            scan_image("app:1", runner)

    @pytest.mark.parametrize("reference", ["--privileged", "-v", "a b", "a;b", ""])
    def test_option_like_references_are_rejected(self, reference: str) -> None:
        with pytest.raises(DockerError, match="valid image reference"):
            scan_image(reference, fake_docker(inspect_document()))

    def test_unexpected_output(self) -> None:
        with pytest.raises(DockerError):
            scan_image("a:1", fake_docker({"not": "a list"}))


class TestCommand:
    def test_terminal_report_and_exit_codes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            cli, "scan_image", lambda ref: analyze_image(info(user="", ports=("22/tcp",)), NOW)
        )
        result = CliRunner().invoke(app, ["docker", "scan", "app:1", "--no-color"])
        assert result.exit_code == 1
        assert "IMG003" in result.output and "Port 22/tcp (SSH)" in result.output
        assert (
            CliRunner().invoke(app, ["docker", "scan", "app:1", "--fail-on", "critical"]).exit_code
            == 0
        )

    def test_json_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli, "scan_image", lambda ref: analyze_image(info(user="app"), NOW))
        document = json.loads(CliRunner().invoke(app, ["docker", "scan", "app:1", "--json"]).stdout)
        assert document["image"]["reference"] == "app:1" and document["findings"] == []

    def test_docker_problems_exit_two_with_a_clear_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken(ref: str) -> None:
            raise DockerError("Docker was not found. Install Docker to scan images.")

        monkeypatch.setattr(cli, "scan_image", broken)
        result = CliRunner().invoke(app, ["docker", "scan", "app:1"])
        assert result.exit_code == 2 and "Docker was not found" in result.output
        assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "created",
    [
        "2026-10-14T15:15:40.72712669+03:00",
        "2026-10-14T12:15:40Z",
        "2026-10-14T12:15:40.123456789Z",
    ],
)
def test_created_timestamps_keep_their_offset(created: str) -> None:
    parsed = image_module._parse_created(created)
    assert parsed is not None
    assert parsed.astimezone(UTC).hour == 12
    assert image_module._parse_created("not a date") is None
    assert image_module._parse_created(None) is None


def test_age_is_never_negative() -> None:
    future = info(created=datetime(2026, 10, 15, tzinfo=UTC))
    assert analyze_image(future, NOW).age_days == 0
