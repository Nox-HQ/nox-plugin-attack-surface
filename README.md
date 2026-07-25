# nox-plugin-attack-surface

**Extract HTTP endpoints and map the attack surface of your application.**

<!-- badges -->
![Track: Dynamic Runtime](https://img.shields.io/badge/track-Dynamic%20Runtime-orange)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8)

---

## Overview

`nox-plugin-attack-surface` performs static endpoint extraction and attack surface inventory for web applications. It discovers every HTTP endpoint defined in source code, identifies potentially unauthenticated routes, flags exposed admin and debug endpoints, detects file upload handling, and locates WebSocket connections. The result is a complete map of your application's external-facing surface area.

Understanding your attack surface is the prerequisite for securing it. Most organizations cannot answer the question "how many endpoints does this service expose, and which ones lack authentication?" This plugin answers that question definitively by parsing route definitions across Go (net/http, Gin, Echo, Chi), Python (Flask, Django, FastAPI), and JavaScript/TypeScript (Express, Koa, Fastify) frameworks.

The plugin uses a two-pass approach: the first pass establishes what the file *is* — which packages it imports, whether it is test code, and whether authentication middleware appears anywhere in it. The second pass extracts routes. If no auth middleware is found in the file, every endpoint defined in that file is flagged as potentially unauthenticated (with exceptions for common public endpoints like `/health`, `/ready`, and `/ping`). This approach acknowledges that auth middleware is typically applied at the router or module level, not per-handler.

### Precision model

A tool that reports 67 endpoints in a codebase with no HTTP routing trains its users to ignore it, so detection is gated on evidence rather than on keywords:

- **Routing constructs, not string literals.** A route is only extracted from a registration call (`mux.HandleFunc`, `r.Get`, `@app.route`, `app.get`) in a file that actually imports `net/http` or a web framework. A `.Get("…")` call in a file that imports no web framework is not a route.
- **Header bags are not routers.** `msg.Header.Get("Subject")` and `r.Header.Get("Authorization")` share a call shape with Chi's `r.Get("/path")`. Receivers such as `Header`, `Form`, `Query` and `Params` are excluded, and the extracted string must be shaped like a URL path.
- **Header names are not endpoints.** `Content-Type`, `Content-Disposition`, `Subject`, `From`, `Date`, `Message-Id` and any `X-` prefixed token are rejected outright, as are MIME media types such as `multipart/mixed`.
- **Mail parsing is not web routing.** A file that imports `net/mail`, `mime`, `mime/multipart` (or `email`/`smtplib`, or `nodemailer`/`mailparser`) and imports *no* web framework is skipped entirely.
- **Comments and string contents are not code.** Every keyword matcher runs against source with comments removed and string literal contents blanked, across block comments, Go raw strings, JS template literals and Python docstrings. A comment describing `multipart/alternative`, an import of `mime/multipart`, and a `strings.Contains(got, "multipart/mixed")` assertion are all documentation or data, not upload handling.
- **File upload means HTTP form APIs.** ATTACK-004 matches `FormFile`, `ParseMultipartForm`, `MultipartReader`, `request.files`, `UploadFile`, `multer(`, `busboy(`, `formidable(` — not the mere presence of the words "multipart" or "upload". `mime/multipart` on its own is MIME composition, which mail code uses constantly.
- **Test files are not attack surface.** See below.

### Test files

ATTACK-001 through ATTACK-005 do **not** fire in test files by default. A route registered in an `httptest` fixture is not reachable in production, and an assertion string is not an endpoint. Test files are recognised by convention: `*_test.go`; `test_*.py`, `*_test.py`, `conftest.py`, anything under `tests/`; `*.test.*`, `*.spec.*`, and anything under `__tests__/`, `__mocks__/` or `cypress/`.

Pass `include_tests: true` to the `scan` tool to inventory test code as well. Doing so lifts only the test-file policy; every other gate above still applies, so MIME assertions in a test file stay silent either way.

## Use Cases

### Pre-Pentest Reconnaissance

Before engaging a penetration testing firm, your security team needs to provide a complete list of endpoints, including which ones are authenticated, which expose admin functionality, and which handle file uploads. This plugin generates that inventory automatically, saving days of manual endpoint mapping.

### Unauthenticated Endpoint Discovery

A developer adds a new endpoint to an Express app but forgets to apply the authentication middleware. This plugin detects the missing auth pattern and flags the endpoint as potentially unauthenticated, catching the oversight before it reaches production.

### Admin/Debug Endpoint Audit

Your application exposes `/admin`, `/debug/pprof`, `/metrics`, or `/graphql/playground` endpoints. In production, these are high-value targets for attackers. This plugin specifically flags these patterns so they can be restricted or removed before deployment.

### Attack Surface Drift Monitoring

Run this plugin in CI on every pull request to track changes to your attack surface over time. New endpoints, removed authentication, or added file upload handlers will appear as new findings, giving your security team visibility into attack surface drift.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-attack-surface
   ```

2. **Create a test file** (`demo/server.js`):

   ```javascript
   const express = require('express');
   const multer = require('multer');
   const WebSocket = require('ws');
   const app = express();

   const upload = multer({ dest: 'uploads/' });

   app.get('/api/users', (req, res) => {
       res.json(users);
   });

   app.post('/api/users', (req, res) => {
       db.create(req.body);
       res.status(201).send();
   });

   app.get('/admin/dashboard', (req, res) => {
       res.render('admin');
   });

   app.post('/api/upload', upload.single('file'), (req, res) => {
       res.json({ filename: req.file.filename });
   });

   app.get('/health', (req, res) => {
       res.send('ok');
   });

   const wss = new WebSocket.Server({ port: 8080 });
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/attack-surface demo/
   ```

4. **Review findings**

   ```
   nox-plugin-attack-surface: 8 findings

   ATTACK-001 [INFO] HTTP endpoint detected: /api/users
     demo/server.js:8:8
     endpoint: /api/users

   ATTACK-002 [MEDIUM] Potentially unauthenticated endpoint: /api/users
     demo/server.js:8:8
     endpoint: /api/users

   ATTACK-001 [INFO] HTTP endpoint detected: /api/users
     demo/server.js:12:12
     endpoint: /api/users

   ATTACK-001 [INFO] HTTP endpoint detected: /admin/dashboard
     demo/server.js:17:17
     endpoint: /admin/dashboard

   ATTACK-003 [MEDIUM] Admin/debug endpoint exposed: /admin/dashboard
     demo/server.js:17:17
     endpoint: /admin/dashboard

   ATTACK-001 [INFO] HTTP endpoint detected: /api/upload
     demo/server.js:21:21
     endpoint: /api/upload

   ATTACK-004 [LOW] File upload handling detected: const upload = multer({ dest: 'uploads/' });
     demo/server.js:6:6

   ATTACK-005 [MEDIUM] WebSocket endpoint detected:
     const wss = new WebSocket.Server({ port: 8080 });
     demo/server.js:29:29
   ```

## Rules

| ID | Description | Severity | Confidence |
|----|-------------|----------|------------|
| ATTACK-001 | HTTP endpoint detected (inventory) | Info | High |
| ATTACK-002 | Potentially unauthenticated endpoint | Medium | Medium |
| ATTACK-003 | Admin/debug endpoint exposed | Medium | High |
| ATTACK-004 | File upload handling detected | Low | Medium |
| ATTACK-005 | WebSocket endpoint detected | Medium | Medium |

### Public Endpoints (Not Flagged by ATTACK-002)

The following endpoints are considered commonly public and are excluded from unauthenticated endpoint warnings: `/health`, `/healthz`, `/ready`, `/readyz`, `/ping`, `/version`, `/`, `/favicon.ico`, `/robots.txt`.

## Supported Languages / File Types

Endpoint extraction requires import evidence: the file must import one of the frameworks below (or, for JS route modules that receive the router as a parameter, use a router-shaped receiver such as `app` or `router`).

| Language | Extensions | Frameworks Detected |
|----------|-----------|---------------------|
| Go | `.go` | net/http (`HandleFunc`, `Handle`, including Go 1.22 `"GET /path"` patterns), Gin, Echo, Chi, gorilla/mux, Fiber, httprouter, fasthttp, Beego |
| Python | `.py` | Flask (`@app.route`), Django (`path`, `re_path`, `url`), FastAPI (`@app.get`, etc.), Starlette, Sanic, Bottle, Quart, Falcon, aiohttp, Tornado |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | Express (`app.get`, `router.post`), Koa (`router.get`), Fastify (`fastify.get`), Hapi, NestJS, Next, restify, polka, Hono |
| TypeScript | `.ts`, `.tsx` | Express, Koa, Fastify (same patterns as JS) |

### Cross-Language Detection

| Pattern | Detection Scope |
|---------|----------------|
| Auth middleware | `authMiddleware`, `requireAuth`, `isAuthenticated`, `jwt.*middleware`, `passport.*`, `@login_required`, `AuthGuard`, `UseGuards`, `Depends(...auth)` |
| Admin/debug paths | `/admin`, `/debug`, `/metrics`, `/health`, `/status`, `/internal`, `/actuator`, `/__debug__`, `/pprof`, `/swagger`, `/graphql`, `/playground` |
| File upload | Go: `.FormFile(`, `.ParseMultipartForm(`, `.MultipartReader(`, `.MultipartForm`. Python: `request.files`, `UploadFile`, `FileField(`, `MultiPartParser`. JS: `multer(`, `busboy(`, `formidable(`, `req.files`, and `.single(`/`.array(`/`.fields(` in files importing an upload library |
| WebSocket | Go: `websocket.Upgrader`, `.Upgrade(`. Python: `websockets.serve(`, `WebSocketHandler`. JS: `new WebSocket(`, `new WebSocket.Server(`, `@WebSocketGateway`. Any language: a registered route whose path or handler names a WebSocket |

## Configuration

This plugin requires no environment configuration.

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| _None_ | This plugin has no environment variables | -- |

### Tool inputs

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `workspace_root` | string | request workspace root | Directory to scan |
| `include_tests` | bool | `false` | Also report findings in test files (see [Test files](#test-files)) |

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-attack-surface
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-attack-surface.git
cd nox-plugin-attack-surface
go build -o nox-plugin-attack-surface .
```

## Development

```bash
# Build
go build ./...

# Run tests
go test ./...

# Run a specific test
go test ./... -run TestExtractEndpointsFindsRealRoutes

# Lint
golangci-lint run

# Run in Docker
docker build -t nox-plugin-attack-surface .
docker run --rm nox-plugin-attack-surface
```

## Architecture

The plugin is built on the Nox plugin SDK and communicates via the Nox plugin protocol over stdio.

**Scan pipeline:**

1. **Workspace walk** (`main.go`) -- Recursively traverses the workspace root, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`, `dist`, and `build` directories, plus test files unless `include_tests` is set.

2. **Scrubbing** (`scrub.go`) -- Each file is projected twice: once with comments removed and string contents kept (route paths live inside string literals), once with comments removed *and* string contents blanked (so prose and data can never match code patterns). The scrubber is stateful and handles block comments, Go raw strings, JS template literals and Python triple-quoted strings.

3. **Two-pass file analysis** (`detect.go`):
   - **Pass 1 (file facts):** Collects imports, classifies the file's web frameworks and mail/MIME packages, and checks for authentication middleware. A file that handles mail/MIME and imports no web framework is dropped here.
   - **Pass 2 (per line):** Extracts routes from registration calls, validating the receiver and the path shape. For each extracted endpoint the plugin emits:
     - **ATTACK-001 (Info):** The endpoint exists.
     - **ATTACK-002 (Medium):** The endpoint appears unauthenticated (no auth middleware in file, and not a common public endpoint).
     - **ATTACK-003 (Medium):** The endpoint matches admin/debug path patterns.
   - Additionally, each non-import line is checked for HTTP file upload APIs (ATTACK-004) and WebSocket constructs (ATTACK-005), against the string-blanked projection.

4. **Output** -- Findings include the extracted endpoint path and the detected framework as metadata, enabling downstream tools to build endpoint inventories and attack surface maps.

The analysis in `detect.go` and `scrub.go` has no dependency on the SDK: every heuristic is a pure function over source text and is unit tested directly in `detect_test.go` and `scrub_test.go`, with end-to-end coverage over `testdata/` in `main_test.go`. `testdata/clean/` is the false-positive corpus and must always produce zero findings.

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-framework`)
3. Write tests for new framework endpoint extraction
4. Ensure `go test ./...` and `golangci-lint run` pass
5. Submit a pull request

## License

Apache-2.0
