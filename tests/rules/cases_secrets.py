from __future__ import annotations

from tests.rules.helpers import (
    AWS_KEY,
    GITHUB_TOKEN,
    LARAVEL,
    PRIVATE_KEY,
    Negative,
    Positive,
    dockerfile,
)

POSITIVE: Positive = {
    "SH001": [
        ({".env": "APP_DEBUG=true\nAPP_ENV=production\n"}, {".env:1"}),
        ({"config/app.php": "<?php\nreturn [\n    'debug' => true,\n];\n"}, {"config/app.php:3"}),
        (dockerfile("FROM node:20\nENV NODE_ENV=development\n"), {"Dockerfile:2"}),
    ],
    "SH201": [
        ({"config.js": f'const k = "{AWS_KEY}";\n'}, {"config.js:1"}),
        ({"deploy.sh": f"export T={GITHUB_TOKEN}\n"}, {"deploy.sh:1"}),
        ({"key.pem": f"{PRIVATE_KEY}\nMIIE\n"}, {"key.pem:1"}),
        ({"app.js": 'const apiKey = "q8Zr2LmP0vXw93TbYk6Nd";\n'}, {"app.js:1"}),
        ({"c.py": 'URL = "postgres://admin:Zx83kLm20Qw@db.internal/app"\n'}, {"c.py:1"}),
    ],
    "SH202": [
        ({".env": "A=1\n"}, {".env"}),
        ({"apps/web/.env.production": "A=1\n"}, {"apps/web/.env.production"}),
    ],
    "SH203": [
        ({"deploy/id_rsa": "k"}, {"deploy/id_rsa"}),
        ({"cert.p12": "k"}, {"cert.p12"}),
    ],
    "SH205": [
        ({**LARAVEL, ".env": "APP_KEY=\n"}, {".env:1"}),
        ({".env": "JWT_SECRET=secret\n"}, {".env:1"}),
        ({".env": "SESSION_SECRET=short\n"}, {".env:1"}),
    ],
    "SH301": [
        ({".env": "A=1\n"}, {".env"}),
        ({".env": "A=1\nB=2\n", ".env.example": "A=\n"}, {".env.example"}),
    ],
    "SH302": [
        ({".env": "A=1\n", ".env.example": "A=\nB=\n"}, {".env"}),
    ],
}

NEGATIVE: Negative = {
    "SH001": [
        {".env.local": "APP_DEBUG=true\n"},
        {".env": "APP_DEBUG=false\n"},
        {"config/app.php": "<?php\nreturn ['debug' => env('APP_DEBUG', false)];\n"},
    ],
    "SH201": [
        {"c.js": 'const apiKey = "your-api-key-goes-here";\n'},
        {"README.md": "AKIAIOSFODNN7EXAMPLE\n"},
        {".gitignore": ".env\n", ".env": f"API_SECRET={GITHUB_TOKEN}\n"},
        {"c.js": "const apiKey = process.env.API_KEY;\n"},
        {"package-lock.json": f'{{"x": "{AWS_KEY}"}}'},
    ],
    "SH202": [
        {".gitignore": ".env\n", ".env": "A=1\n"},
        {".env": ""},
        {".env.example": "A=1\n"},
    ],
    "SH203": [
        {"id_rsa.pub": "k"},
        {".gitignore": "*.p12\n", "cert.p12": "k"},
    ],
    "SH204": [{".env.example": "A=\n"}],
    "SH205": [
        {".env": "APP_KEY=base64:abc\n"},
        {".env": "APP_KEY=\n"},
        {".env": "JWT_SECRET=q8Zr2LmP0vXw93TbYk6NdAf7\n"},
        {".env": "STRIPE_PUBLISHABLE_SECRET=pk\n"},
    ],
    "SH301": [
        {".env": "A=1\n", ".env.example": "A=\n"},
        {".env.example": "A=\n"},
    ],
    "SH302": [
        {".env": "A=1\n", ".env.example": "A=\n"},
        {".env.example": "A=\nB=\n"},
    ],
}
