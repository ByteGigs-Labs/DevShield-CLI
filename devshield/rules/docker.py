from __future__ import annotations

import re
import shlex
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.parsers import effective_user, final_stage, from_parts, stages
from devshield.core.rule import Rule

DOCKER = frozenset({Framework.DOCKER})
DATABASE_IMAGES = re.compile(r"postgres|mysql|mariadb|mongo|redis|memcached|elasticsearch", re.I)
SECRET_KEY = re.compile(r"SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY", re.I)
BUILD_TOOLS = re.compile(
    r"build-essential|\bgcc\b|g\+\+|\bmake\b|npm run build|yarn build|pnpm build|go build"
    r"|cargo build|\bmvn\b|gradle",
)
INSTALL = re.compile(
    r"npm (?:ci|install)|yarn install|pnpm install|composer install|pip install|bundle install"
)
ARCHIVE = re.compile(r"\.(?:tar|tgz|tar\.gz|tar\.xz|tar\.bz2)$")
HOST_PORT = re.compile(r"^(?:0\.0\.0\.0:)?\d+:\d+(?:/\w+)?$")
DEVELOPMENT_FILE = re.compile(
    r"(?:^|[./_-])(?:dev|development|local|test|override)(?:[./_-]|$)", re.I
)
NON_ROOT_IMAGE = re.compile(r"nonroot|unprivileged|chainguard|distroless|scratch", re.I)
SECRET_FILE_KEY = re.compile(r"_(?:FILE|PATH)$", re.I)
CACHE_MOUNT = "--mount=type=cache"


def _production_dockerfiles(ctx: ProjectContext) -> list[str]:
    return [f for f in ctx.dockerfiles if not DEVELOPMENT_FILE.search(f.rsplit("/", 1)[-1])]


def _split_image(image: str) -> tuple[str, str, bool]:
    name, _, digest = image.partition("@")
    tag = ""
    if ":" in name.rsplit("/", 1)[-1]:
        name, _, tag = name.rpartition(":")
    return name, tag, bool(digest)


def _short_port(port: object) -> str | None:
    if isinstance(port, dict):
        published = port.get("published")
        exposed = port.get("host_ip") in (None, "0.0.0.0")
        return f"{published}:{port.get('target')}" if published and exposed else None
    return str(port)


def _env_pairs(args: str) -> list[tuple[str, str]]:
    try:
        tokens = shlex.split(args)
    except ValueError:
        return []
    if tokens and "=" not in tokens[0]:
        return [(tokens[0], " ".join(tokens[1:]))]
    return [tuple(t.split("=", 1)) for t in tokens if "=" in t]  # type: ignore[misc]


class UnpinnedBaseImage(Rule):
    id = "PERF101"
    title = "Base image not pinned to a version"
    severity = Severity.MEDIUM
    category = Category.DOCKER
    applies_to = DOCKER
    description = (
        "The latest tag changes without warning, so builds are not reproducible and an "
        "upstream release can break or compromise your image."
    )
    remediation = "Pin the image to a specific version tag, or better a digest (image@sha256:...)."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.dockerfiles:
            aliases: set[str] = set()
            for instruction in ctx.dockerfile(file):
                parts = from_parts(instruction) if instruction.name == "FROM" else None
                if parts is None:
                    continue
                image, alias = parts
                if alias:
                    aliases.add(alias.lower())
                name, tag, digest = _split_image(image)
                if image.lower() in aliases or image == "scratch" or "$" in image:
                    continue
                if digest or (tag and tag != "latest"):
                    continue
                yield self.finding(
                    f"{name} uses {'the latest tag' if tag else 'no tag (latest)'}",
                    file=file,
                    line=instruction.line,
                )


class RunsAsRoot(Rule):
    id = "PERF102"
    title = "Container runs as root"
    severity = Severity.MEDIUM
    category = Category.DOCKER
    applies_to = DOCKER
    description = (
        "A process running as root inside the container turns any application bug into full "
        "control of the container and makes escapes easier."
    )
    remediation = "Create an unprivileged user and switch to it with a USER instruction."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in _production_dockerfiles(ctx):
            instructions = ctx.dockerfile(file)
            stage = final_stage(instructions)
            base = from_parts(stage[0]) if stage and stage[0].name == "FROM" else None
            if not stage or (base and NON_ROOT_IMAGE.search(base[0])):
                continue
            if effective_user(instructions) in {None, "root", "0"}:
                yield self.finding(
                    "The final stage never switches away from root",
                    file=file,
                    line=stage[0].line,
                )


class MissingDockerignore(Rule):
    id = "PERF103"
    title = "No .dockerignore"
    severity = Severity.LOW
    category = Category.DOCKER
    applies_to = DOCKER
    description = (
        "Without .dockerignore the whole project, including .git, node_modules and .env, is "
        "sent to the build and can end up inside the image."
    )
    remediation = "Add a .dockerignore listing .git, node_modules, .env and build output."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.dockerfiles:
            directory = file.rpartition("/")[0]
            ignore = f"{directory}/.dockerignore" if directory else ".dockerignore"
            specific = f"{file}.dockerignore"
            if not any(ctx.exists(candidate) for candidate in (ignore, ".dockerignore", specific)):
                yield self.finding("No .dockerignore next to this Dockerfile", file=file)


class SingleStageBuild(Rule):
    id = "PERF104"
    title = "Build tools left in the final image"
    severity = Severity.LOW
    category = Category.DOCKER
    applies_to = DOCKER
    description = (
        "Compilers and build caches in the runtime image make it larger and widen its "
        "attack surface."
    )
    remediation = "Use a multi-stage build and copy only the built artifacts into the final stage."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in _production_dockerfiles(ctx):
            instructions = ctx.dockerfile(file)
            if len(stages(instructions)) != 1:
                continue
            for run in (i for i in instructions if i.name == "RUN" and BUILD_TOOLS.search(i.args)):
                yield self.finding(
                    "Single-stage image installs or runs build tools", file=file, line=run.line
                )
                break


class AddInsteadOfCopy(Rule):
    id = "PERF105"
    title = "ADD used instead of COPY"
    severity = Severity.LOW
    category = Category.DOCKER
    applies_to = DOCKER
    description = (
        "ADD also downloads URLs and unpacks archives, which is surprising and unverified. "
        "COPY only copies files."
    )
    remediation = "Use COPY, and download remote files with curl plus a checksum check."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.dockerfiles:
            for add in (i for i in ctx.dockerfile(file) if i.name == "ADD"):
                sources = [t for t in add.args.split()[:-1] if not t.startswith("--")]
                if any(s.startswith(("http://", "https://")) for s in sources):
                    yield self.finding(
                        "ADD downloads a remote file",
                        file=file,
                        line=add.line,
                        severity=Severity.MEDIUM,
                    )
                elif not all(ARCHIVE.search(s) for s in sources):
                    yield self.finding("Use COPY for local files", file=file, line=add.line)


class PackageInstallHygiene(Rule):
    id = "PERF106"
    title = "Package install leaves caches or extras"
    severity = Severity.LOW
    category = Category.DOCKER
    applies_to = DOCKER
    description = "Package caches and recommended packages bloat every layer they are written to."
    remediation = (
        "Use `apt-get install --no-install-recommends` and remove /var/lib/apt/lists in the "
        "same RUN; use `apk add --no-cache`."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.dockerfiles:
            for run in (
                i for i in ctx.dockerfile(file) if i.name == "RUN" and CACHE_MOUNT not in i.args
            ):
                problems = []
                if "apt-get install" in run.args:
                    if "--no-install-recommends" not in run.args:
                        problems.append("apt-get install without --no-install-recommends")
                    if "/var/lib/apt/lists" not in run.args:
                        problems.append("apt lists are not removed")
                if "apk add" in run.args and "--no-cache" not in run.args:
                    problems.append("apk add without --no-cache")
                if problems:
                    yield self.finding(
                        f"Layer bloat: {'; '.join(problems)}", file=file, line=run.line
                    )


class CacheUnfriendlyLayers(Rule):
    id = "PERF107"
    title = "Dependency install after copying the whole project"
    severity = Severity.LOW
    category = Category.DOCKER
    applies_to = DOCKER
    description = (
        "Copying all sources before installing dependencies invalidates the dependency layer "
        "on every code change, so every build reinstalls everything."
    )
    remediation = "COPY only the manifest and lockfile, install dependencies, then COPY the rest."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in _production_dockerfiles(ctx):
            for stage in stages(ctx.dockerfile(file)).values():
                copied_all = False
                for instruction in stage:
                    if instruction.name == "COPY" and re.search(
                        r"(?:^|\s)\.(?:/)?\s+\S+$", instruction.args
                    ):
                        copied_all = True
                    elif (
                        copied_all
                        and instruction.name == "RUN"
                        and INSTALL.search(instruction.args)
                    ):
                        yield self.finding(
                            "Dependencies are installed after COPY . .",
                            file=file,
                            line=instruction.line,
                        )
                        break


class MissingHealthcheck(Rule):
    id = "PERF108"
    title = "No HEALTHCHECK"
    severity = Severity.INFO
    category = Category.DOCKER
    applies_to = DOCKER
    description = (
        "Without a health check orchestrators cannot tell a hung container from a healthy one."
    )
    remediation = "Add a HEALTHCHECK instruction that calls a lightweight endpoint."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in _production_dockerfiles(ctx):
            stage = final_stage(ctx.dockerfile(file))
            if stage and not any(i.name == "HEALTHCHECK" for i in stage):
                yield self.finding("The final stage has no HEALTHCHECK", file=file)


class ComposeExposure(Rule):
    id = "SH011"
    title = "Risky docker-compose service configuration"
    severity = Severity.HIGH
    category = Category.SECURITY
    applies_to = DOCKER
    description = (
        "Privileged containers, host networking, the Docker socket and publicly bound database "
        "ports each give an attacker a way past the container boundary or straight to your data."
    )
    remediation = (
        "Drop privileged/host settings, bind ports to 127.0.0.1, and keep databases on an "
        "internal network."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.compose_files:
            document = ctx.yaml(file)
            services = document.get("services") if isinstance(document, dict) else None
            for name, service in (services if isinstance(services, dict) else {}).items():
                if not isinstance(service, dict):
                    continue
                for message, severity in self._problems(service, file):
                    yield self.finding(
                        f"Service '{name}' {message}",
                        file=file,
                        line=ctx.line_of(file, "services", name),
                        severity=severity,
                    )

    @staticmethod
    def _problems(service: dict[str, object], file: str) -> Iterator[tuple[str, Severity | None]]:
        if service.get("privileged") is True:
            yield "runs privileged", None
        if service.get("network_mode") == "host" or service.get("pid") == "host":
            yield "shares the host network or PID namespace", Severity.MEDIUM
        volumes = service.get("volumes")
        if isinstance(volumes, list) and any("docker.sock" in str(v) for v in volumes):
            yield "mounts the Docker socket", None
        ports = service.get("ports")
        if DATABASE_IMAGES.search(str(service.get("image", ""))) and isinstance(ports, list):
            local = Severity.LOW if DEVELOPMENT_FILE.search(file.rsplit("/", 1)[-1]) else None
            for port in ports:
                text = _short_port(port)
                if text and HOST_PORT.match(text):
                    yield f"publishes database port {text} on all interfaces", local


class SecretsInImage(Rule):
    id = "SH012"
    title = "Secret baked into Dockerfile"
    severity = Severity.HIGH
    category = Category.SECURITY
    applies_to = DOCKER
    description = (
        "ENV and ARG values stay readable in the image history for anyone who can pull it."
    )
    remediation = "Pass secrets at runtime, or use BuildKit `--mount=type=secret` during the build."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.dockerfiles:
            for instruction in ctx.dockerfile(file):
                if instruction.name not in {"ENV", "ARG"}:
                    continue
                pairs = (
                    _env_pairs(instruction.args)
                    if instruction.name == "ENV"
                    else [tuple(instruction.args.split("=", 1))]
                    if "=" in instruction.args
                    else []
                )
                for key, value in pairs:
                    if (
                        SECRET_KEY.search(key)
                        and not SECRET_FILE_KEY.search(key)
                        and value
                        and "$" not in value
                    ):
                        yield self.finding(
                            f"{instruction.name} {key} sets a literal secret",
                            file=file,
                            line=instruction.line,
                        )
