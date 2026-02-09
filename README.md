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

The plugin uses a two-pass approach: the first pass scans the entire file for authentication middleware patterns. If no auth middleware is found in the file, every endpoint defined in that file is flagged as potentially unauthenticated (with exceptions for common public endpoints like `/health`, `/ready`, and `/ping`). This approach acknowledges that auth middleware is typically applied at the router or module level, not per-handler.

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

| Language | Extensions | Frameworks Detected |
|----------|-----------|---------------------|
| Go | `.go` | net/http (`HandleFunc`, `Handle`), Gin (`GET`, `POST`, etc.), Echo, Chi |
| Python | `.py` | Flask (`@app.route`), Django (`path`, `re_path`, `url`), FastAPI (`@app.get`, etc.) |
| JavaScript | `.js`, `.jsx` | Express (`app.get`, `router.post`), Koa (`router.get`), Fastify (`fastify.get`) |
| TypeScript | `.ts`, `.tsx` | Express, Koa, Fastify (same patterns as JS) |

### Cross-Language Detection

| Pattern | Detection Scope |
|---------|----------------|
| Auth middleware | `authMiddleware`, `requireAuth`, `isAuthenticated`, `jwt.*middleware`, `passport.*`, `@login_required`, `AuthGuard`, `UseGuards`, `Depends(...auth)` |
| Admin/debug paths | `/admin`, `/debug`, `/metrics`, `/health`, `/status`, `/internal`, `/actuator`, `/__debug__`, `/pprof`, `/swagger`, `/graphql`, `/playground` |
| File upload | `multipart`, `FormFile`, `upload`, `multer`, `FileField`, `UploadFile`, `busboy`, `formidable` |
| WebSocket | `websocket`, `ws://`, `wss://`, `Upgrader`, `socket.io`, `@WebSocket`, `@SubscribeMessage` |

## Configuration

This plugin requires no configuration.

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| _None_ | This plugin has no environment variables | -- |

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
go test ./... -run TestExpressEndpointExtraction

# Lint
golangci-lint run

# Run in Docker
docker build -t nox-plugin-attack-surface .
docker run --rm nox-plugin-attack-surface
```

## Architecture

The plugin is built on the Nox plugin SDK and communicates via the Nox plugin protocol over stdio.

**Scan pipeline:**

1. **Workspace walk** -- Recursively traverses the workspace root, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`, `dist`, and `build` directories.

2. **Two-pass file analysis:**
   - **Pass 1 (auth middleware scan):** Reads all lines and checks for authentication middleware patterns anywhere in the file. Sets a `hasAuthInFile` flag.
   - **Pass 2 (endpoint extraction):** Iterates over each line and attempts to extract HTTP endpoint paths using framework-specific regex patterns. For each extracted endpoint, the plugin emits:
     - **ATTACK-001 (Info):** The endpoint exists.
     - **ATTACK-002 (Medium):** The endpoint appears unauthenticated (no auth middleware in file, and not a common public endpoint).
     - **ATTACK-003 (Medium):** The endpoint matches admin/debug path patterns.
   - Additionally, each line is checked for file upload handling (ATTACK-004) and WebSocket patterns (ATTACK-005).

3. **Endpoint extraction** -- Framework-specific regex patterns extract the URL path from route definitions. The `extractEndpoint` function dispatches to the correct set of patterns based on file extension.

4. **Output** -- Findings include the extracted endpoint path as metadata, enabling downstream tools to build endpoint inventories and attack surface maps.

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-framework`)
3. Write tests for new framework endpoint extraction
4. Ensure `go test ./...` and `golangci-lint run` pass
5. Submit a pull request

## License

Apache-2.0
