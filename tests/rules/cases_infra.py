from __future__ import annotations

from tests.rules.helpers import (
    NODE,
    WORKFLOW,
    Negative,
    Positive,
    dockerfile,
    workflow,
)

COMPOSE = "docker-compose.yml"
JOBS = "on: push\njobs:\n  a:\n    steps:\n"
SHA = "0123456789abcdef0123456789abcdef01234567"
README = "word " * 80
LOCKED = '{"packages": {"": {"dependencies": {"a": "1"}}}}'
SPREAD = (
    '{"packages": {"node_modules/x": {"version": "1.0.0"}, '
    '"node_modules/a/node_modules/x": {"version": "2.0.0"}, '
    '"node_modules/b/node_modules/x": {"version": "3.0.0"}}}'
)
PROJECT = {"package.json": NODE}

POSITIVE: Positive = {
    "PERF101": [
        (dockerfile("FROM node:latest\n"), {"Dockerfile:1"}),
        (dockerfile("FROM node\n"), {"Dockerfile:1"}),
    ],
    "PERF102": [
        (dockerfile('FROM node:20\nCMD ["node"]\n'), {"Dockerfile:1"}),
        (dockerfile("FROM node:20\nUSER root\n"), {"Dockerfile:1"}),
    ],
    "PERF103": [(dockerfile("FROM node:20\n"), {"Dockerfile"})],
    "PERF104": [(dockerfile("FROM node:20\nRUN npm run build\n"), {"Dockerfile:2"})],
    "PERF105": [
        (
            dockerfile(
                "FROM a:1\nADD app.js /app/\nADD https://x.test/y.sh /y\nADD app.tar.gz /app\n"
            ),
            {"Dockerfile:2", "Dockerfile:3"},
        ),
    ],
    "PERF106": [
        (dockerfile("FROM a:1\nRUN apt-get update && apt-get install -y curl\n"), {"Dockerfile:2"}),
        (dockerfile("FROM a:1\nRUN apk add curl\n"), {"Dockerfile:2"}),
    ],
    "PERF107": [(dockerfile("FROM node:20\nCOPY . .\nRUN npm ci\n"), {"Dockerfile:3"})],
    "PERF108": [(dockerfile("FROM node:20\n"), {"Dockerfile"})],
    "SH011": [
        (
            {
                COMPOSE: "services:\n  db:\n    image: postgres:16\n    privileged: true\n"
                '    ports:\n      - "5432:5432"\n    volumes:\n'
                "      - /var/run/docker.sock:/var/run/docker.sock\n    network_mode: host\n"
            },
            {f"{COMPOSE}:2"},
        ),
    ],
    "SH012": [
        (
            dockerfile("FROM a:1\nENV API_TOKEN=abc123\nARG DB_PASSWORD=hunter2\n"),
            {"Dockerfile:2", "Dockerfile:3"},
        ),
        (dockerfile("FROM a:1\nENV SECRET_KEY some-value\n"), {"Dockerfile:2"}),
    ],
    "PERF301": [
        ({"package.json": '{"dependencies": {"a": "1"}}'}, {"package.json"}),
        (
            {
                "package.json": '{"dependencies": {"a": "1", "b": "1"}}',
                "package-lock.json": LOCKED,
            },
            {"package-lock.json"},
        ),
        ({"composer.json": '{"require": {"a/b": "1"}}'}, {"composer.json"}),
        (
            {
                "composer.json": '{"require": {"php": "8", "a/b": "1"}}',
                "composer.lock": '{"packages": []}',
            },
            {"composer.lock"},
        ),
    ],
    "PERF302": [
        (
            {"package.json": '{\n  "dependencies": {"moment": "2", "dayjs": "1"}\n}'},
            {"package.json:2"},
        ),
        ({"package-lock.json": SPREAD}, {"package-lock.json"}),
    ],
    "PERF303": [
        ({"package.json": '{\n  "dependencies": {\n    "eslint": "9"\n  }\n}'}, {"package.json:3"}),
        (
            {"composer.json": '{\n  "require": {\n    "phpunit/phpunit": "11"\n  }\n}'},
            {"composer.json:3"},
        ),
    ],
    "PERF304": [
        (
            {
                "package.json": '{\n  "dependencies": {\n    "a": "*",\n    "b": "latest",\n'
                '    "c": ">=1.0.0"\n  }\n}'
            },
            {"package.json:3", "package.json:4", "package.json:5"},
        ),
        ({"composer.json": '{"require": {"a/b": "dev-master"}}'}, {"composer.json:1"}),
    ],
    "DX003": [
        (
            workflow("name: x\non: push\njobs:\n  a:\n    steps:\n      - run: echo hi\n"),
            {f"{WORKFLOW}:3"},
        ),
        (
            workflow("on: push\npermissions: write-all\njobs:\n  a:\n    steps: []\n"),
            {f"{WORKFLOW}:2"},
        ),
    ],
    "DX004": [
        (
            workflow(
                "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
                "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            ),
            {f"{WORKFLOW}:5"},
        ),
    ],
    "DX005": [
        (
            workflow(
                JOBS + "      - uses: foo/bar@v1\n      - uses: actions/checkout@v4\n"
                f"      - uses: ./local\n      - uses: org/x@{SHA}\n"
            ),
            {f"{WORKFLOW}:5", f"{WORKFLOW}:6"},
        ),
    ],
    "DX006": [(workflow(JOBS + "      - run: npm ci\n"), {f"{WORKFLOW}:2"})],
    "DX010": [(workflow(JOBS + "      - run: echo ${{ secrets.TOKEN }}\n"), {f"{WORKFLOW}:5"})],
    "DX011": [
        (
            workflow(JOBS + '      - run: echo "${{ github.event.issue.title }}"\n'),
            {f"{WORKFLOW}:5"},
        ),
    ],
    "DX001": [(PROJECT, {"-"})],
    "DX002": [(PROJECT, {"-"})],
    "DX007": [
        (
            {"package.json": '{"version": "1.0.0"}', "composer.json": '{"version": "v2.0.0"}'},
            {"-"},
        ),
    ],
    "DX008": [(PROJECT, {"-"}), ({**PROJECT, ".gitignore": "dist\n"}, {".gitignore"})],
    "DX009": [({**PROJECT, "big.bin": "a" * (5 * 1024 * 1024 + 1)}, {"big.bin"})],
    "DOC001": [(PROJECT, {"-"}), ({**PROJECT, "README.md": "hi"}, {"README.md"})],
    "DOC002": [({**PROJECT, "README.md": README}, {"-"})],
    "DOC003": [({**PROJECT, "README.md": README}, {"-"})],
}

NEGATIVE: Negative = {
    "PERF101": [
        dockerfile("FROM node:20-alpine\n"),
        dockerfile("FROM node:20 AS build\nFROM build\n"),
        dockerfile("FROM node@sha256:abc\n"),
        dockerfile("FROM scratch\n"),
        dockerfile("ARG V=20\nFROM node:${V}\n"),
    ],
    "PERF102": [dockerfile("FROM node:20\nUSER node\n")],
    "PERF103": [{**dockerfile("FROM node:20\n"), ".dockerignore": ".git\n"}],
    "PERF104": [
        dockerfile(
            "FROM node:20 AS b\nRUN npm run build\nFROM node:20-slim\nCOPY --from=b /a /a\n"
        ),
    ],
    "PERF105": [dockerfile("FROM a:1\nADD app.tar.gz /app\nCOPY a /a\n")],
    "PERF106": [
        dockerfile(
            "FROM a:1\nRUN apt-get update && apt-get install -y --no-install-recommends curl "
            "&& rm -rf /var/lib/apt/lists/*\nRUN apk add --no-cache curl\n"
        ),
    ],
    "PERF107": [dockerfile("FROM node:20\nCOPY package.json ./\nRUN npm ci\nCOPY . .\n")],
    "PERF108": [dockerfile("FROM node:20\nHEALTHCHECK CMD true\n")],
    "SH011": [
        {
            COMPOSE: 'services:\n  db:\n    image: postgres:16\n    ports:\n      - "127.0.0.1:5432:5432"\n'
            "  web:\n    image: nginx\n"
        },
    ],
    "SH012": [dockerfile("FROM a:1\nENV NODE_ENV=production\nARG NPM_TOKEN\nENV TOKEN=$T\n")],
    "PERF301": [
        {"package.json": '{"dependencies": {"a": "1"}}', "package-lock.json": LOCKED},
        {"composer.json": '{"type": "library", "require": {}}'},
        {
            "composer.json": '{"require": {"a/b": "1"}}',
            "composer.lock": '{"packages": [{"name": "a/b"}]}',
        },
    ],
    "PERF302": [
        {"package.json": '{"dependencies": {"dayjs": "1"}}'},
        {
            "package-lock.json": SPREAD.replace(
                '"node_modules/b/node_modules/x": {"version": "3.0.0"}', '"y": {"version": "1.0.0"}'
            )
        },
    ],
    "PERF303": [
        {"package.json": '{"devDependencies": {"eslint": "9"}}'},
        {"composer.json": '{"require-dev": {"phpunit/phpunit": "11"}}'},
    ],
    "PERF304": [
        {
            "package.json": '{"dependencies": {"a": "^1.2.3", "b": "~2", "c": ">=1.0 <2.0", "d": "1.2.3"}}'
        },
    ],
    "DX003": [
        workflow("on: push\npermissions:\n  contents: read\njobs:\n  a:\n    steps: []\n"),
        workflow("on: push\njobs:\n  a:\n    permissions: read-all\n    steps: []\n"),
    ],
    "DX004": [
        workflow(
            "on: pull_request\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        ),
        workflow(
            "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
        ),
    ],
    "DX005": [workflow(JOBS + f"      - uses: ./local\n      - uses: org/x@{SHA}\n")],
    "DX006": [
        workflow(
            JOBS + "      - uses: actions/setup-node@v4\n        with:\n          cache: npm\n"
            "      - run: npm ci\n"
        ),
    ],
    "DX010": [
        workflow(
            JOBS + "      - run: ./deploy.sh\n        env:\n          T: ${{ secrets.TOKEN }}\n"
        ),
    ],
    "DX011": [workflow(JOBS + '      - run: echo "${{ github.sha }}"\n')],
    "DX001": [{**PROJECT, "tests/a.test.js": ""}, {"README.md": "x"}],
    "DX002": [{**PROJECT, WORKFLOW: "on: push\n"}],
    "DX007": [
        {"package.json": '{"version": "1.0.0"}', "composer.json": '{"version": "v1.0.0"}'},
    ],
    "DX008": [{**PROJECT, ".gitignore": "node_modules\n"}],
    "DX009": [{**PROJECT, "small.bin": "a" * 1000}],
    "SH013": [{**PROJECT, "a.txt": "x"}],
    "DOC001": [{**PROJECT, "README.md": README}],
    "DOC002": [{**PROJECT, "LICENSE": "MIT"}],
    "DOC003": [
        {**PROJECT, "README.md": README, "CONTRIBUTING.md": "x", "CHANGELOG.md": "x"},
        PROJECT,
    ],
}


EXTRA_NEGATIVE: Negative = {
    "PERF102": [
        dockerfile("FROM gcr.io/distroless/static:nonroot\nCOPY a /a\n"),
        dockerfile("FROM node:20 AS base\nUSER node\nFROM base\nCMD x\n"),
        {"Dockerfile.dev": "FROM node:20\nCMD x\n"},
    ],
    "PERF103": [{**dockerfile("FROM node:20\n"), "Dockerfile.dockerignore": ".git\n"}],
    "PERF104": [{"Dockerfile.dev": "FROM node:20\nRUN npm run build\n"}],
    "PERF106": [
        dockerfile(
            "FROM a:1\nRUN --mount=type=cache,target=/var/cache/apt apt-get install -y curl\n"
        ),
    ],
    "PERF108": [{"Dockerfile.local": "FROM node:20\n"}],
    "SH001": [
        dockerfile("FROM node:20 AS dev\nENV NODE_ENV=development\nFROM node:20-slim\nUSER node\n")
    ],
    "SH012": [dockerfile("FROM a:1\nENV DB_PASSWORD_FILE=/run/secrets/db\n")],
    "DX003": [workflow("on: workflow_call\njobs:\n  a:\n    steps: []\n")],
    "DX005": [workflow(JOBS + "      - uses: docker://alpine@sha256:abc\n")],
    "DX006": [workflow(JOBS + "      - run: yarn test\n")],
    "DX010": [
        workflow(JOBS + "      - run: echo ${{ secrets.TOKEN }} | docker login --password-stdin\n"),
    ],
    "DX011": [
        workflow(JOBS + '      - run: echo "${{ github.event.pull_request.base.ref }}"\n'),
    ],
    "PERF301": [
        {"package.json": '{"name": "lib", "main": "index.js", "dependencies": {"a": "1"}}'}
    ],
    "PERF302": [{"package.json": '{"devDependencies": {"moment": "2", "dayjs": "1"}}'}],
    "DX001": [{**PROJECT, "Tests/Unit/AThing.php": ""}],
    "DX002": [{**PROJECT, "cloudbuild.yaml": "steps: []\n"}],
    "DX007": [{"package.json": '{"version": "0.0.0"}', "composer.json": '{"version": "1.4.0"}'}],
    "DOC001": [{**PROJECT, "docs/README.md": README}],
    "DOC002": [
        {**PROJECT, "LICENSE-MIT": "MIT"},
        {"package.json": '{"private": true}'},
        {"package.json": '{"license": "MIT"}'},
    ],
}
NEGATIVE = {
    k: [*NEGATIVE.get(k, []), *EXTRA_NEGATIVE.get(k, [])] for k in {*NEGATIVE, *EXTRA_NEGATIVE}
}
