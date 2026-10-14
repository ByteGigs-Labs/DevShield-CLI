from __future__ import annotations

from tests.rules.helpers import EXPRESS, LARAVEL, NEXT, NODE, REACT, Negative, Positive

JWT = "const jwt = require('jsonwebtoken');\n"
SESSION_START = "const session = require('express-session');\napp.use(session({\n  secret: s,\n"

POSITIVE: Positive = {
    "SH002": [
        ({"package.json": NODE, "server.js": "app.use(cors({ origin: '*' }));\n"}, {"server.js:1"}),
        (
            {
                "package.json": NODE,
                "server.js": "const cors = require('cors');\napp.use(cors());\n",
            },
            {"server.js:2"},
        ),
    ],
    "SH003": [
        ({"package.json": EXPRESS, "app.js": "const app = express();\n"}, {"package.json:2"}),
    ],
    "SH004": [
        ({"package.json": EXPRESS, "app.js": "const app = express();\n"}, {"app.js:1"}),
    ],
    "SH008": [
        (
            {
                "package.json": NODE,
                "a.js": (
                    "eval(x);\nconst f = new Function('a', body);\n"
                    "exec(`ls ${dir}`);\nexecSync('ls ' + dir);\nexec('ls -la');\n"
                ),
            },
            {"a.js:1", "a.js:2", "a.js:3", "a.js:4"},
        ),
    ],
    "SH101": [
        (
            {
                "package.json": EXPRESS,
                "app.js": SESSION_START + "  cookie: { secure: false }\n}));\n",
            },
            {"app.js:4", "app.js:2"},
        ),
    ],
    "SH102": [
        ({"package.json": NODE, "a.js": JWT + "jwt.verify(token, process.env.S);\n"}, {"a.js:2"}),
        (
            {
                "package.json": NODE,
                "a.js": JWT + "jwt.sign({ id: 1 }, 'hunter2hunter2', { expiresIn: '1h' });\n",
            },
            {"a.js:2"},
        ),
        (
            {"package.json": NODE, "a.js": JWT + "jwt.verify(t, k, { algorithms: ['none'] });\n"},
            {"a.js:2"},
        ),
        ({"package.json": NODE, "a.js": JWT + "jwt.sign({ id: 1 }, process.env.S);\n"}, {"a.js:2"}),
    ],
    "SH103": [
        ({"package.json": EXPRESS, "app.js": "app.post('/login', h);\n"}, {"app.js:1"}),
    ],
    "SH005": [
        (
            {"package.json": REACT, "App.jsx": "<div dangerouslySetInnerHTML={{__html: x}} />\n"},
            {"App.jsx:1"},
        ),
    ],
    "SH006": [
        (
            {"package.json": REACT, ".env": "VITE_API_SECRET=abc\nVITE_API_URL=http://x\n"},
            {".env:1"},
        ),
        ({"package.json": NEXT, ".env.example": "NEXT_PUBLIC_AUTH_SECRET=\n"}, {".env.example:1"}),
        (
            {"package.json": NEXT, ".env": "NEXT_PUBLIC_SERVICE_TOKEN=" + "sk_" + "abc123\n"},
            {".env:1"},
        ),
    ],
    "SH007": [
        ({"package.json": NEXT, "next.config.js": "module.exports = {};\n"}, {"next.config.js"}),
    ],
    "PERF201": [
        (
            {
                "package.json": REACT,
                "vite.config.js": "export default { build: { sourcemap: true } };\n",
            },
            {"vite.config.js:1"},
        ),
    ],
    "PERF202": [
        (
            {
                "package.json": REACT,
                "a.js": "import moment from 'moment';\nconst _ = require('lodash');\n"
                "import debounce from 'lodash/debounce';\n",
            },
            {"a.js:1", "a.js:2"},
        ),
        ({"package.json": REACT, "dist/app.js": "a" * 600_000}, {"dist/app.js"}),
    ],
    "PERF203": [
        ({"package.json": REACT, "public/hero.png": "a" * 600_000}, {"public/hero.png"}),
        ({"package.json": NEXT, "pages/i.tsx": "<img src='/a.png' />\n"}, {"pages/i.tsx:1"}),
    ],
    "SH009": [
        (
            {
                **LARAVEL,
                "config/cors.php": "<?php\nreturn [\n    'allowed_origins' => ['*'],\n"
                "    'supports_credentials' => true,\n];\n",
            },
            {"config/cors.php:3"},
        ),
    ],
    "SH010": [({**LARAVEL, "public/.env.backup": "A=1\n"}, {"public/.env.backup"})],
    "SH104": [
        (
            {
                **LARAVEL,
                "config/session.php": "<?php\nreturn [\n    'secure' => env('SESSION_SECURE_COOKIE'),\n"
                "    'http_only' => false,\n    'same_site' => null,\n];\n",
            },
            {"config/session.php:3", "config/session.php:4", "config/session.php:5"},
        ),
    ],
    "SH105": [
        (
            {**LARAVEL, "routes/web.php": "<?php\nRoute::post('/login', [A::class, 'login']);\n"},
            {"routes/web.php:2"},
        ),
    ],
    "PERF001": [
        ({**LARAVEL, "Dockerfile": "FROM php:8.3\nRUN composer install\n"}, {"Dockerfile"}),
    ],
}

NEGATIVE: Negative = {
    "SH002": [
        {"package.json": NODE, "server.js": "app.use(cors({ origin: 'https://a.com' }));\n"},
        {"server.js": "app.use(cors());\n"},
    ],
    "SH003": [
        {"package.json": '{"dependencies": {"express": "4", "helmet": "7"}}'},
        {"package.json": EXPRESS, "a.js": "res.setHeader('X-Content-Type-Options', 'nosniff');\n"},
    ],
    "SH004": [
        {
            "package.json": EXPRESS,
            "app.js": "const app = express();\napp.disable('x-powered-by');\n",
        },
        {
            "package.json": '{"dependencies": {"express": "4", "helmet": "7"}}',
            "a.js": "express();\n",
        },
    ],
    "SH008": [
        {"package.json": NODE, "a.test.js": "eval(x);\n"},
        {"package.json": NODE, "a.js": "exec('ls -la');\n"},
    ],
    "SH101": [
        {
            "package.json": EXPRESS,
            "app.js": SESSION_START
            + "  cookie: { secure: true, httpOnly: true, sameSite: 'lax' }\n}));\n",
        },
        {"package.json": EXPRESS, "app.js": "app.use(session({ secret: s }));\n"},
    ],
    "SH102": [
        {
            "package.json": NODE,
            "a.js": JWT + "jwt.verify(t, process.env.S, { algorithms: ['HS256'] });\n",
        },
        {
            "package.json": NODE,
            "a.js": JWT + "jwt.sign({ id: 1 }, process.env.S, { expiresIn: '1h' });\n",
        },
    ],
    "SH103": [
        {
            "package.json": '{"dependencies": {"express": "4", "express-rate-limit": "7"}}',
            "app.js": "app.post('/login', h);\n",
        },
        {"package.json": EXPRESS, "app.js": "app.get('/', h);\n"},
    ],
    "SH005": [
        {
            "package.json": REACT,
            "App.jsx": "import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{__html: x}} />\n",
        },
    ],
    "SH006": [
        {"package.json": REACT, ".env": "VITE_STRIPE_PUBLISHABLE_KEY=pk\nVITE_API_URL=http://x\n"},
        {"package.json": NODE, ".env": "VITE_API_SECRET=abc\n"},
    ],
    "SH007": [
        {
            "package.json": NEXT,
            "next.config.js": "headers: [{ key: 'Content-Security-Policy', value: '' }]\n",
        },
        {"package.json": NEXT},
    ],
    "PERF201": [
        {
            "package.json": REACT,
            "vite.config.js": "export default { build: { sourcemap: false } };\n",
        },
    ],
    "PERF202": [
        {"package.json": REACT, "a.js": "import dayjs from 'dayjs';\n"},
        {"package.json": REACT, "dist/app.js": "a" * 1000},
    ],
    "PERF203": [
        {"package.json": REACT, "public/icon.png": "a" * 1000},
        {"package.json": REACT, "a.jsx": "<img src='/a.png' />\n"},
    ],
    "SH009": [
        {
            **LARAVEL,
            "config/cors.php": "<?php\nreturn ['allowed_origins' => ['https://a.com']];\n",
        },
        {"config/cors.php": "<?php\nreturn ['allowed_origins' => ['*']];\n"},
    ],
    "SH010": [{**LARAVEL, "public/index.php": "<?php\n"}],
    "SH104": [
        {
            **LARAVEL,
            "config/session.php": "<?php\nreturn ['secure' => true, 'http_only' => true, 'same_site' => 'lax'];\n",
        },
        {
            **LARAVEL,
            ".env": "SESSION_SECURE_COOKIE=true\n",
            "config/session.php": "<?php\nreturn ['secure' => env('SESSION_SECURE_COOKIE'), 'same_site' => 'lax'];\n",
        },
    ],
    "SH105": [
        {
            **LARAVEL,
            "routes/web.php": "<?php\nRoute::post('/login', [A::class, 'l'])->middleware('throttle:5,1');\n",
        },
    ],
    "PERF001": [
        {**LARAVEL, "Dockerfile": "FROM php:8.3\nRUN php artisan optimize\n"},
        LARAVEL,
    ],
}


EXTRA_NEGATIVE: Negative = {
    "SH002": [{"package.json": NODE, "server.js": "app.use(cors());\n"}],
    "SH008": [
        {"package.json": NODE, "a.js": "redis.eval(script, 0);\neval('1 + 1');\n"},
        {"package.json": NODE, "a.js": "// eval(userInput)\n"},
    ],
    "SH101": [
        {
            "package.json": EXPRESS,
            "app.js": "const s = require('express-session');\napp.use(s({ secret: x, cookie: cookieOptions }));\n",
        },
    ],
    "SH102": [
        {"package.json": NODE, "a.js": JWT + "jwt.verify(t, process.env.S, verifyOptions);\n"},
        {"package.json": NODE, "a.js": JWT + "jwt.sign(payload, process.env.S);\n"},
        {"package.json": NODE, "a.js": "jwt.verify(token, 'literal');\n"},
        {
            "package.json": NODE,
            "a.js": JWT
            + "jwt.verify(\n  token,\n  process.env.S,\n  {\n    issuer: 'x',\n    algorithms,\n  },\n);\n",
        },
    ],
    "SH103": [
        {"package.json": EXPRESS, "app.js": "app.post('/authors', h);\napp.get('/login', h);\n"},
    ],
    "SH005": [
        {
            "package.json": REACT,
            "A.jsx": "<script dangerouslySetInnerHTML={{ __html: JSON.stringify(ld) }} />\n",
        },
        {
            "package.json": REACT,
            "A.jsx": "<p dangerouslySetInnerHTML={{ __html: '<b>hi</b>' }} />\n",
        },
    ],
    "SH006": [
        {
            "package.json": NEXT,
            ".env": "NEXT_PUBLIC_MAPBOX_TOKEN=pk.abc\nVITE_ANALYTICS_API_KEY=abc123\n",
        },
    ],
    "SH007": [
        {
            "package.json": NEXT,
            "next.config.js": "module.exports = {};\n",
            "vercel.json": '{"headers": [{"key": "Content-Security-Policy"}]}',
        },
        {
            "package.json": '{"dependencies": {"next": "14", "next-secure-headers": "2"}}',
            "next.config.js": "module.exports = {};\n",
        },
    ],
    "PERF202": [{"package.json": REACT, "pages/api/x.js": "import _ from 'lodash';\n"}],
    "PERF203": [
        {"package.json": NEXT, "pages/i.tsx": "<img src='/logo.svg' />\n"},
        {
            "package.json": NEXT,
            "pages/i.tsx": "{/* eslint-disable-next-line @next/next/no-img-element */}\n<img src='/a.png' />\n",
        },
    ],
    "SH105": [
        {
            **LARAVEL,
            "routes/web.php": "<?php\nRoute::get('/login', [A::class, 'show']);\nRoute::post('/authors', [B::class, 'x']);\n",
        },
    ],
}
NEGATIVE = {
    k: [*NEGATIVE.get(k, []), *EXTRA_NEGATIVE.get(k, [])] for k in {*NEGATIVE, *EXTRA_NEGATIVE}
}
