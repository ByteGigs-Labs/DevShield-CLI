from __future__ import annotations

from tests.rules.helpers import (
    ASPNET,
    DJANGO,
    FASTAPI,
    FLASK,
    NEST,
    SPRING,
    Negative,
    Positive,
)

CFN_HEAD = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n"
CFN_BUCKET = CFN_HEAD + "  Data:\n    Type: AWS::S3::Bucket\n    Properties:\n"

POSITIVE: Positive = {
    "SH001": [
        ({**DJANGO, "web/settings.py": "import os\nDEBUG = True\n"}, {"web/settings.py:2"}),
        (
            {**DJANGO, "web/settings/production.py": "DEBUG = True\n"},
            {"web/settings/production.py:1"},
        ),
        ({**FLASK, "app.py": "app.run(host='0.0.0.0', debug=True)\n"}, {"app.py:1"}),
        ({**FASTAPI, "main.py": "app = FastAPI(debug=True)\n"}, {"main.py:1"}),
        ({**FLASK, ".env.production": "FLASK_DEBUG=1\n"}, {".env.production:1"}),
        ({**DJANGO, ".env.production": "DEBUG=True\n"}, {".env.production:1"}),
        (
            {
                **ASPNET,
                "Program.cs": "var app = builder.Build();\napp.UseDeveloperExceptionPage();\n",
            },
            {"Program.cs:2"},
        ),
        (
            {
                "Dockerfile": "FROM mcr.microsoft.com/dotnet/aspnet:8.0\nENV ASPNETCORE_ENVIRONMENT=Development\n"
            },
            {"Dockerfile:2"},
        ),
    ],
    "SH002": [
        (
            {
                "package.json": NEST,
                "src/main.ts": "const app = await NestFactory.create(AppModule);\napp.enableCors();\n",
            },
            {"src/main.ts:2"},
        ),
        (
            {"package.json": NEST, "src/main.ts": "app.enableCors({ origin: true });\n"},
            {"src/main.ts:1"},
        ),
    ],
    "SH003": [
        ({"package.json": NEST, "src/main.ts": "const app = 1;\n"}, {"package.json:1"}),
    ],
    "SH014": [
        (
            {**DJANGO, "web/settings.py": "ALLOWED_HOSTS = ['*']\n"},
            {"web/settings.py:1"},
        ),
        (
            {**DJANGO, "web/settings/base.py": "X = 1\nALLOWED_HOSTS = ['example.com', '*']\n"},
            {"web/settings/base.py:2"},
        ),
    ],
    "SH015": [
        (
            {
                **DJANGO,
                "web/settings.py": "DEBUG = False\nINSTALLED_APPS = []\nSECRET_KEY = os.environ['K']\n",
            },
            {"web/settings.py:2"},
        ),
        (
            {
                **DJANGO,
                "web/settings.py": "DEBUG = False\nINSTALLED_APPS = []\nSECURE_SSL_REDIRECT = True\n",
            },
            {"web/settings.py:2"},
        ),
    ],
    "SH016": [
        (
            {
                **FASTAPI,
                "main.py": "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n",
            },
            {"main.py:1"},
        ),
        (
            {**FLASK, "app.py": "from flask_cors import CORS\nCORS(app)\n"},
            {"app.py:2"},
        ),
        ({**DJANGO, "web/settings.py": "CORS_ALLOW_ALL_ORIGINS = True\n"}, {"web/settings.py:1"}),
        (
            {**SPRING, "src/main/java/A.java": '@CrossOrigin(origins = "*")\npublic class A {}\n'},
            {"src/main/java/A.java:1"},
        ),
        (
            {**SPRING, "src/main/java/C.java": 'registry.addMapping("/**").allowedOrigins("*");\n'},
            {"src/main/java/C.java:1"},
        ),
        (
            {**ASPNET, "Program.cs": "policy.AllowAnyOrigin().AllowAnyMethod();\n"},
            {"Program.cs:1"},
        ),
        (
            {
                **SPRING,
                "src/main/resources/application.properties": "spring.mvc.cors.allowed-origins=*\n",
            },
            {"src/main/resources/application.properties:1"},
        ),
    ],
    "SH017": [
        (
            {**FASTAPI, "main.py": "from fastapi import FastAPI\napp = FastAPI(title='x')\n"},
            {"main.py:2"},
        ),
        ({**ASPNET, "Program.cs": "app.UseSwagger();\napp.UseSwaggerUI();\n"}, {"Program.cs:1"}),
    ],
    "SH018": [
        (
            {
                **SPRING,
                "src/main/resources/application.properties": "management.endpoints.web.exposure.include=*\n",
            },
            {"src/main/resources/application.properties:1"},
        ),
        (
            {
                **SPRING,
                "src/main/resources/application.yml": (
                    "management:\n  endpoints:\n    web:\n      exposure:\n        include: health,env\n"
                ),
            },
            {"src/main/resources/application.yml:5"},
        ),
        (
            {
                **SPRING,
                "src/main/resources/application.properties": "spring.h2.console.enabled=true\nmanagement.endpoint.shutdown.enabled=true\n",
            },
            {
                "src/main/resources/application.properties:1",
                "src/main/resources/application.properties:2",
            },
        ),
        (
            {
                **SPRING,
                "src/main/resources/application-prod.properties": "server.error.include-stacktrace=always\n",
            },
            {"src/main/resources/application-prod.properties:1"},
        ),
    ],
    "SH019": [
        (
            {
                **FLASK,
                "app.py": "import os\nos.system(f'ls {path}')\neval(user_input)\nexec('x = 1')\n",
            },
            {"app.py:2", "app.py:3"},
        ),
        (
            {**DJANGO, "a.py": "import subprocess\nsubprocess.run(f'tar {name}', shell=True)\n"},
            {"a.py:2"},
        ),
        (
            {
                **FASTAPI,
                "a.py": "import pickle\ndata = pickle.loads(blob)\nconf = yaml.load(text)\n",
            },
            {"a.py:2", "a.py:3"},
        ),
    ],
    "SH020": [
        (
            {
                **DJANGO,
                "a.py": 'cursor.execute(f"SELECT * FROM t WHERE id = {pk}")\nUser.objects.raw("SELECT * FROM u WHERE n = \'%s\'" % name)\n',
            },
            {"a.py:1", "a.py:2"},
        ),
        (
            {
                **FLASK,
                "a.py": "db.execute('SELECT * FROM t WHERE a = ' + value)\nrows = db.execute(\"x {}\".format(v))\n",
            },
            {"a.py:1", "a.py:2"},
        ),
        (
            {
                **SPRING,
                "src/main/java/R.java": 'em.createQuery("from User where name = \'" + name + "\'");\n',
            },
            {"src/main/java/R.java:1"},
        ),
        (
            {
                **ASPNET,
                "Repo.cs": "db.Users.FromSqlRaw($\"SELECT * FROM Users WHERE Name = '{name}'\");\n",
            },
            {"Repo.cs:1"},
        ),
    ],
    "SH106": [
        (
            {
                **DJANGO,
                "web/settings.py": "SESSION_COOKIE_SECURE = False\nCSRF_COOKIE_SECURE = True\n",
            },
            {"web/settings.py:1"},
        ),
        (
            {**DJANGO, "web/settings.py": "DEBUG = False\nINSTALLED_APPS = []\n"},
            {"web/settings.py:2"},
        ),
        ({**FLASK, "app.py": "app.config['SESSION_COOKIE_HTTPONLY'] = False\n"}, {"app.py:1"}),
        (
            {
                **SPRING,
                "src/main/resources/application.properties": "server.servlet.session.cookie.secure=false\n",
            },
            {"src/main/resources/application.properties:1"},
        ),
        (
            {**ASPNET, "Program.cs": "options.Cookie.SecurePolicy = CookieSecurePolicy.None;\n"},
            {"Program.cs:1"},
        ),
    ],
    "SH107": [
        (
            {
                **DJANGO,
                "web/settings.py": "MIDDLEWARE = ['django.middleware.security.SecurityMiddleware']\n",
            },
            {"web/settings.py:1"},
        ),
        ({**DJANGO, "views.py": "@csrf_exempt\ndef hook(request): pass\n"}, {"views.py:1"}),
        ({**FLASK, "app.py": "app.config['WTF_CSRF_ENABLED'] = False\n"}, {"app.py:1"}),
        (
            {**SPRING, "src/main/java/S.java": "http\n    .csrf().disable()\n    .build();\n"},
            {"src/main/java/S.java:2"},
        ),
        (
            {**SPRING, "src/main/java/S.java": "http.csrf(AbstractHttpConfigurer::disable);\n"},
            {"src/main/java/S.java:1"},
        ),
        ({**ASPNET, "C.cs": "[IgnoreAntiforgeryToken]\npublic class C {}\n"}, {"C.cs:1"}),
    ],
    "SH108": [
        (
            {
                **SPRING,
                "src/main/java/S.java": "http.authorizeHttpRequests(a -> a\n    .anyRequest()\n    .permitAll());\n",
            },
            {"src/main/java/S.java:2"},
        ),
        (
            {**SPRING, "src/main/java/S.java": 'auth.requestMatchers("/**").permitAll();\n'},
            {"src/main/java/S.java:1"},
        ),
    ],
    "SH109": [
        ({"package.json": NEST, "src/main.ts": "bootstrap();\n"}, {"src/main.ts"}),
    ],
    "SH206": [
        (
            {**DJANGO, "web/settings.py": "SECRET_KEY = 'django-insecure-abc'\n"},
            {"web/settings.py:1"},
        ),
        ({**FLASK, "app.py": "app.secret_key = 'dev'\n"}, {"app.py:1"}),
        (
            {
                **FLASK,
                "config.py": "class C:\n    SECRET_KEY = os.environ.get('K') or 'fallback'\n",
            },
            {"config.py:2"},
        ),
        ({**FASTAPI, "auth.py": 'SECRET_KEY: str = "09d25e094faa"\n'}, {"auth.py:1"}),
        ({**FLASK, "app.py": "app.config['SECRET_KEY'] = 'abc123'\n"}, {"app.py:1"}),
    ],
    "SH207": [
        (
            {
                **SPRING,
                "src/main/resources/application.properties": "spring.datasource.password=hunter2hunter2\n",
            },
            {"src/main/resources/application.properties:1"},
        ),
        (
            {
                **SPRING,
                "src/main/resources/application.yml": "spring:\n  datasource:\n    password: s3cr3tpass\n",
            },
            {"src/main/resources/application.yml:3"},
        ),
        (
            {
                **ASPNET,
                "appsettings.json": '{\n  "ConnectionStrings": {\n    "Default": "Server=db;User Id=sa;Password=Sup3rSecret!;"\n  }\n}\n',
            },
            {"appsettings.json:3"},
        ),
        (
            {
                **ASPNET,
                "appsettings.json": '{\n  "Jwt": {\n    "Key": "0123456789abcdef0123456789abcdef"\n  }\n}\n',
            },
            {"appsettings.json:3"},
        ),
    ],
    "SH208": [
        (
            {
                **DJANGO,
                "web/settings.py": "DATABASES = {\n    'default': {\n        'PASSWORD': 'hunter2',\n    }\n}\n",
            },
            {"web/settings.py:3"},
        ),
    ],
    "SH303": [
        (
            {
                **SPRING,
                "src/main/resources/application.properties": "spring.jpa.hibernate.ddl-auto=update\n",
            },
            {"src/main/resources/application.properties:1"},
        ),
        (
            {
                **SPRING,
                "src/main/resources/application.yml": "spring:\n  jpa:\n    hibernate:\n      ddl-auto: create-drop\n",
            },
            {"src/main/resources/application.yml:4"},
        ),
    ],
    "SH401": [
        ({"main.tf": 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'}, {"main.tf:2"}),
        (
            {
                "main.tf": 'resource "aws_s3_bucket_public_access_block" "b" {\n  block_public_acls = false\n  block_public_policy = true\n}\n'
            },
            {"main.tf:2"},
        ),
        (
            {
                "main.tf": 'resource "aws_s3_bucket_policy" "p" {\n  policy = jsonencode({\n    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject" }]\n  })\n}\n'
            },
            {"main.tf:2"},
        ),
        ({"template.yaml": CFN_BUCKET + "      AccessControl: PublicRead\n"}, {"template.yaml:6"}),
        (
            {
                "template.yaml": CFN_BUCKET
                + "      PublicAccessBlockConfiguration:\n        BlockPublicAcls: false\n"
            },
            {"template.yaml:7"},
        ),
        (
            {
                "template.yaml": (
                    CFN_HEAD
                    + "  P:\n    Type: AWS::S3::BucketPolicy\n    Properties:\n      PolicyDocument:\n"
                    + "        Statement:\n          - Effect: Allow\n            Principal: '*'\n            Action: s3:GetObject\n"
                )
            },
            {"template.yaml:6"},
        ),
    ],
    "SH402": [
        (
            {
                "main.tf": 'resource "aws_iam_policy" "p" {\n  policy = jsonencode({\n    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]\n  })\n}\n'
            },
            {"main.tf:2"},
        ),
        (
            {
                "main.tf": 'data "aws_iam_policy_document" "d" {\n  statement {\n    actions   = ["*"]\n    resources = ["arn:aws:s3:::x"]\n  }\n}\n'
            },
            {"main.tf:2"},
        ),
        (
            {
                "template.yaml": (
                    CFN_HEAD
                    + "  P:\n    Type: AWS::IAM::Policy\n    Properties:\n      PolicyDocument:\n        Statement:\n"
                    + "          - Effect: Allow\n            Action: '*'\n            Resource: '*'\n"
                )
            },
            {"template.yaml:3"},
        ),
    ],
    "SH403": [
        (
            {
                "main.tf": 'resource "aws_security_group" "g" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
            },
            {"main.tf:2"},
        ),
        (
            {
                "main.tf": 'resource "aws_security_group_rule" "r" {\n  type        = "ingress"\n  from_port   = 5432\n  to_port     = 5432\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
            },
            {"main.tf:1"},
        ),
        (
            {
                "template.yaml": (
                    CFN_HEAD
                    + "  G:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n      SecurityGroupIngress:\n"
                    + "        - IpProtocol: tcp\n          FromPort: 3389\n          ToPort: 3389\n          CidrIp: 0.0.0.0/0\n"
                )
            },
            {"template.yaml:3"},
        ),
    ],
    "SH404": [
        ({"main.tf": 'resource "aws_db_instance" "d" {\n  engine = "mysql"\n}\n'}, {"main.tf:1"}),
        ({"main.tf": 'resource "aws_ebs_volume" "v" {\n  encrypted = false\n}\n'}, {"main.tf:2"}),
        (
            {
                "template.yaml": CFN_HEAD
                + "  D:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      Engine: mysql\n"
            },
            {"template.yaml:3"},
        ),
    ],
    "SH405": [
        (
            {"main.tf": 'resource "aws_db_instance" "d" {\n  publicly_accessible = true\n}\n'},
            {"main.tf:2"},
        ),
        (
            {
                "template.yaml": CFN_HEAD
                + "  D:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      PubliclyAccessible: true\n"
            },
            {"template.yaml:6"},
        ),
    ],
}

NEGATIVE: Negative = {
    "SH001": [
        {**DJANGO, "web/settings.py": "DEBUG = os.environ.get('DEBUG') == '1'\n"},
        {**DJANGO, "web/settings/dev.py": "DEBUG = True\n"},
        {**FLASK, "app.py": "app.run(host='0.0.0.0')\n"},
        {**FLASK, ".env.production": "FLASK_DEBUG=0\n"},
        {"package.json": '{"name": "x"}', ".env.production": "DEBUG=True\n"},
        {
            **ASPNET,
            "Program.cs": "if (app.Environment.IsDevelopment())\n{\n    app.UseDeveloperExceptionPage();\n}\n",
        },
    ],
    "SH002": [
        {
            "package.json": NEST,
            "src/main.ts": "app.enableCors({ origin: 'https://example.com' });\n",
        },
    ],
    "SH003": [
        {"package.json": '{"dependencies": {"@nestjs/core": "10", "helmet": "7"}}'},
    ],
    "SH014": [
        {**DJANGO, "web/settings.py": "ALLOWED_HOSTS = ['example.com']\n"},
        {**DJANGO, "web/settings/dev.py": "ALLOWED_HOSTS = ['*']\n"},
        {"web/settings.py": "ALLOWED_HOSTS = ['*']\n"},
    ],
    "SH015": [
        {
            **DJANGO,
            "web/settings.py": "DEBUG = False\nINSTALLED_APPS = []\nSECURE_SSL_REDIRECT = True\nSECURE_HSTS_SECONDS = 31536000\n",
        },
        {**DJANGO, "web/settings.py": "DEBUG = True\nINSTALLED_APPS = []\n"},
    ],
    "SH016": [
        {
            **FASTAPI,
            "main.py": "app.add_middleware(CORSMiddleware, allow_origins=['https://example.com'])\n",
        },
        {
            **FLASK,
            "app.py": "from flask_cors import CORS\nCORS(app, origins=['https://example.com'])\n",
        },
        {**FLASK, "app.py": "CORS(app)\n"},
        {
            **SPRING,
            "src/main/java/C.java": 'registry.addMapping("/**").allowedOrigins("https://example.com");\n',
        },
        {**ASPNET, "Program.cs": 'policy.WithOrigins("https://example.com");\n'},
    ],
    "SH017": [
        {**FASTAPI, "main.py": "app = FastAPI(docs_url=None, redoc_url=None)\n"},
        {**FASTAPI, "main.py": "app = FastAPI(docs_url='/docs' if dev else None)\n"},
        {
            **ASPNET,
            "Program.cs": "if (app.Environment.IsDevelopment())\n{\n    app.UseSwagger();\n}\n",
        },
    ],
    "SH018": [
        {
            **SPRING,
            "src/main/resources/application.properties": "management.endpoints.web.exposure.include=health,info\n",
        },
        {
            **SPRING,
            "src/main/resources/application-dev.properties": "management.endpoints.web.exposure.include=*\n",
        },
        {
            **SPRING,
            "src/main/resources/application.properties": "spring.h2.console.enabled=false\n",
        },
    ],
    "SH019": [
        {
            **FLASK,
            "app.py": "import os\nos.system('ls -la')\nvalue = ast.literal_eval(text)\nmodel.eval()\n",
        },
        {**DJANGO, "a.py": "subprocess.run(['tar', name])\nsubprocess.run('ls', shell=True)\n"},
        {
            **FASTAPI,
            "a.py": "conf = yaml.load(text, Loader=yaml.SafeLoader)\nyaml.safe_load(text)\n",
        },
    ],
    "SH020": [
        {
            **DJANGO,
            "a.py": "cursor.execute('SELECT * FROM t WHERE id = %s', [pk])\nUser.objects.raw('SELECT 1')\n",
        },
        {**FLASK, "a.py": "db.execute(text('SELECT * FROM t WHERE a = :a'), {'a': value})\n"},
        {
            **SPRING,
            "src/main/java/R.java": 'em.createQuery("from User where name = :n").setParameter("n", name);\n',
        },
        {
            **ASPNET,
            "Repo.cs": 'db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}");\n',
        },
    ],
    "SH106": [
        {**DJANGO, "web/settings.py": "SESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True\n"},
        {**DJANGO, "web/settings.py": "DEBUG = True\nINSTALLED_APPS = []\n"},
        {
            **SPRING,
            "src/main/resources/application.properties": "server.servlet.session.cookie.secure=true\n",
        },
        {
            **SPRING,
            "src/main/resources/application-dev.properties": "server.servlet.session.cookie.secure=false\n",
        },
    ],
    "SH107": [
        {
            **DJANGO,
            "web/settings.py": "MIDDLEWARE = ['django.middleware.csrf.CsrfViewMiddleware']\n",
        },
        {**FLASK, "app.py": "app.config['WTF_CSRF_ENABLED'] = True\n"},
        {**SPRING, "src/main/java/S.java": "http.csrf(Customizer.withDefaults());\n"},
    ],
    "SH108": [
        {
            **SPRING,
            "src/main/java/S.java": 'a.requestMatchers("/public/**").permitAll().anyRequest().authenticated();\n',
        },
    ],
    "SH109": [
        {
            "package.json": NEST,
            "src/main.ts": "app.useGlobalPipes(new ValidationPipe({ whitelist: true }));\n",
        },
    ],
    "SH206": [
        {**DJANGO, "web/settings.py": "SECRET_KEY = os.environ['SECRET_KEY']\n"},
        {**FLASK, "app.py": "app.secret_key = os.environ.get('SECRET_KEY')\n"},
        {**DJANGO, "web/settings/dev.py": "SECRET_KEY = 'dev-only'\n"},
        {**FLASK, "tests/test_app.py": "app.secret_key = 'test'\n"},
    ],
    "SH207": [
        {
            **SPRING,
            "src/main/resources/application.properties": "spring.datasource.password=${DB_PASSWORD}\nspring.datasource.url=jdbc:h2:mem:x\njwt.expiration=3600\nsecurity.token.name=x\n",
        },
        {**SPRING, "src/main/resources/application.properties": "spring.datasource.password=\n"},
        {
            **ASPNET,
            "appsettings.json": '{\n  "Logging": {"LogLevel": {"Default": "Information"}},\n  "ConnectionStrings": {"Default": "Server=db;Integrated Security=true;"}\n}\n',
        },
    ],
    "SH208": [
        {
            **DJANGO,
            "web/settings.py": "DATABASES = {'default': {'PASSWORD': os.environ['DB_PASSWORD']}}\n",
        },
    ],
    "SH303": [
        {
            **SPRING,
            "src/main/resources/application.properties": "spring.jpa.hibernate.ddl-auto=validate\n",
        },
        {
            **SPRING,
            "src/main/resources/application-dev.properties": "spring.jpa.hibernate.ddl-auto=create\n",
        },
    ],
    "SH401": [
        {
            "main.tf": 'resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\nresource "aws_s3_bucket_public_access_block" "x" {\n  block_public_acls = true\n}\n'
        },
        {"template.yaml": CFN_BUCKET + "      AccessControl: Private\n"},
        {
            "main.tf": 'resource "aws_s3_bucket_policy" "p" {\n  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::1:root" }, Action = "s3:GetObject" }] })\n}\n'
        },
    ],
    "SH402": [
        {
            "main.tf": 'resource "aws_iam_policy" "p" {\n  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "arn:aws:s3:::x/*" }] })\n}\n'
        },
        {
            "main.tf": 'data "aws_iam_policy_document" "d" {\n  statement {\n    effect  = "Deny"\n    actions = ["*"]\n    resources = ["*"]\n  }\n}\n'
        },
    ],
    "SH403": [
        {
            "main.tf": 'resource "aws_security_group" "g" {\n  ingress {\n    from_port   = 443\n    to_port     = 443\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["10.0.0.0/8"]\n  }\n}\n'
        },
    ],
    "SH404": [
        {
            "main.tf": 'resource "aws_db_instance" "d" {\n  storage_encrypted = true\n}\nresource "aws_db_instance" "r" {\n  replicate_source_db = "x"\n}\n'
        },
        {
            "template.yaml": CFN_HEAD
            + "  D:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      StorageEncrypted: true\n"
        },
    ],
    "SH405": [
        {"main.tf": 'resource "aws_db_instance" "d" {\n  publicly_accessible = false\n}\n'},
    ],
}
