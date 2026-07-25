package main

import (
	"regexp"
	"strings"
)

// This file holds the static analysis. It deliberately has no dependency on the
// nox SDK: every function here is a pure transformation over source text, so the
// detection heuristics can be unit tested directly.
//
// Design notes (why the analysis is shaped this way):
//
//  1. Endpoint extraction keys off *routing constructs*, not off any string
//     literal that happens to sit next to an HTTP-ish identifier. A route match
//     must (a) come from a file that actually imports a web framework or
//     net/http, (b) use a receiver that is not a well known header/parameter bag,
//     and (c) yield a string that is shaped like a URL path.
//  2. Mail/MIME parsing is not web routing. A file that imports net/mail, mime,
//     mime/multipart (or their Python/JS equivalents) and does *not* import any
//     web framework is skipped entirely — it has no HTTP attack surface.
//  3. Comments and string literal contents are removed before any keyword
//     matcher runs. Documentation and test assertions describe code, they are not
//     code, and matching them was the source of whole classes of false hits.
//  4. Test files are not attack surface. They are skipped by default and can be
//     re-enabled with the `include_tests` tool input.

// language identifies the source language of a file.
type language string

const (
	langUnknown language = ""
	langGo      language = "go"
	langPython  language = "python"
	langJS      language = "javascript"
)

// extLanguages maps file extensions to the language analysed for that file.
var extLanguages = map[string]language{
	".go":  langGo,
	".py":  langPython,
	".js":  langJS,
	".jsx": langJS,
	".mjs": langJS,
	".cjs": langJS,
	".ts":  langJS,
	".tsx": langJS,
}

// languageFor returns the language for a file extension, or langUnknown.
func languageFor(ext string) language { return extLanguages[strings.ToLower(ext)] }

// --- rule identifiers ---

const (
	ruleEndpoint   = "ATTACK-001"
	ruleUnauth     = "ATTACK-002"
	ruleAdminDebug = "ATTACK-003"
	ruleUpload     = "ATTACK-004"
	ruleWebSocket  = "ATTACK-005"
)

// rawFinding is a detection expressed in analysis terms; main.go maps it onto
// the SDK finding model.
type rawFinding struct {
	rule      string
	line      int
	endpoint  string
	evidence  string
	framework string
}

// fileFacts summarises what a source file *is*, established before any finding
// is emitted.
type fileFacts struct {
	lang      language
	isTest    bool
	web       bool   // imports net/http or a web framework
	framework string // the most specific web framework detected
	mailMIME  bool   // imports mail / MIME parsing packages
	uploadLib bool   // imports a file upload middleware library
	hasAuth   bool   // references authentication middleware
	imports   []string
}

// routingSuppressed reports whether the file should be excluded from endpoint,
// upload and WebSocket detection: mail/MIME parsing code with no web imports
// exposes no HTTP surface, however many header names it mentions.
func (f fileFacts) routingSuppressed() bool { return f.mailMIME && !f.web }

// sourceAnalysis is the result of analysing one source file.
type sourceAnalysis struct {
	facts    fileFacts
	findings []rawFinding
}

// analyzeSource runs the full analysis over the lines of one source file.
func analyzeSource(path string, lang language, lines []string) sourceAnalysis {
	code, codeOnly := scrubLines(lang, lines)

	facts := gatherFacts(path, lang, code)
	analysis := sourceAnalysis{facts: facts}
	if facts.routingSuppressed() {
		return analysis
	}

	for i := range code {
		lineNum := i + 1
		analysis.findings = append(analysis.findings, endpointFindings(code[i], lineNum, facts)...)
		if isImportLine(lang, code[i]) {
			continue
		}
		if m := matchUpload(facts, codeOnly[i]); m != "" {
			analysis.findings = append(analysis.findings, rawFinding{rule: ruleUpload, line: lineNum, evidence: m})
		}
		if m := matchWebSocket(lang, codeOnly[i]); m != "" {
			analysis.findings = append(analysis.findings, rawFinding{rule: ruleWebSocket, line: lineNum, evidence: m})
		}
	}
	return analysis
}

// endpointFindings emits the endpoint rules for a single line of code.
func endpointFindings(codeLine string, lineNum int, facts fileFacts) []rawFinding {
	var out []rawFinding
	for _, ep := range extractEndpoints(codeLine, facts) {
		out = append(out, rawFinding{
			rule: ruleEndpoint, line: lineNum, endpoint: ep, framework: facts.framework,
		})
		if isWebSocketRoute(ep, codeLine) {
			out = append(out, rawFinding{rule: ruleWebSocket, line: lineNum, evidence: ep})
		}
		if !facts.hasAuth && !isCommonPublicEndpoint(ep) {
			out = append(out, rawFinding{
				rule: ruleUnauth, line: lineNum, endpoint: ep, framework: facts.framework,
			})
		}
		if reAdminDebug.MatchString(ep) {
			out = append(out, rawFinding{
				rule: ruleAdminDebug, line: lineNum, endpoint: ep, framework: facts.framework,
			})
		}
	}
	return out
}

// --- file classification ---

var (
	reGoImportSingle = regexp.MustCompile(`^\s*import\s+(?:[\w.]+\s+)?"([^"]+)"`)
	reGoImportOpen   = regexp.MustCompile(`^\s*import\s*\(`)
	reGoImportEntry  = regexp.MustCompile(`^\s*(?:[\w.]+\s+)?"([^"]+)"`)
	rePyImport       = regexp.MustCompile(`^\s*(?:from\s+([\w.]+)\s+import\b|import\s+([\w.]+))`)
	reJSImport       = regexp.MustCompile(`(?:require\s*\(\s*['"]([^'"]+)['"]|from\s+['"]([^'"]+)['"]|import\s+['"]([^'"]+)['"])`)

	// Auth middleware patterns. Matched against comment-stripped code so that a
	// "TODO: add authenticate()" note cannot silence ATTACK-002.
	reAuthMiddleware = regexp.MustCompile(`(?i)(auth.?middleware|requireAuth|isAuthenticated|authenticate|jwt.?middleware|passport\.|@login_required|@requires_auth|AuthGuard|UseGuards|Depends\(.*auth)`)

	// Admin/debug endpoints, matched against an already validated route path.
	reAdminDebug = regexp.MustCompile(`(?i)(/admin|/debug|/metrics|/health|/status|/internal|/actuator|/__debug__|/pprof|/swagger|/graphql|/playground)`)
)

// gatherFacts derives the file level context used to gate every rule.
func gatherFacts(path string, lang language, code []string) fileFacts {
	facts := fileFacts{lang: lang, isTest: isTestFile(path, lang)}
	facts.imports = collectImports(lang, code)

	for _, imp := range facts.imports {
		if name, ok := webFrameworkFor(lang, imp); ok && (facts.framework == "" || facts.framework == "net/http") {
			facts.web = true
			facts.framework = name
		} else if ok {
			facts.web = true
		}
		if isMailMIMEImport(lang, imp) {
			facts.mailMIME = true
		}
		if matchesAny(imp, uploadLibs[lang]) {
			facts.uploadLib = true
		}
	}
	for _, line := range code {
		if reAuthMiddleware.MatchString(line) {
			facts.hasAuth = true
			break
		}
	}
	return facts
}

// collectImports returns the module paths imported by the file.
func collectImports(lang language, code []string) []string {
	switch lang {
	case langGo:
		return collectGoImports(code)
	case langPython:
		return collectMatches(code, rePyImport)
	case langJS:
		return collectMatches(code, reJSImport)
	default:
		return nil
	}
}

// collectGoImports walks single imports and `import ( ... )` blocks.
func collectGoImports(code []string) []string {
	var out []string
	inBlock := false
	for _, line := range code {
		switch {
		case inBlock:
			if strings.HasPrefix(strings.TrimSpace(line), ")") {
				inBlock = false
				continue
			}
			if m := reGoImportEntry.FindStringSubmatch(line); m != nil {
				out = append(out, m[1])
			}
		case reGoImportOpen.MatchString(line):
			inBlock = true
		default:
			if m := reGoImportSingle.FindStringSubmatch(line); m != nil {
				out = append(out, m[1])
			}
		}
	}
	return out
}

// collectMatches gathers every non-empty capture group of re across lines.
func collectMatches(code []string, re *regexp.Regexp) []string {
	var out []string
	for _, line := range code {
		for _, m := range re.FindAllStringSubmatch(line, -1) {
			for _, g := range m[1:] {
				if g != "" {
					out = append(out, g)
				}
			}
		}
	}
	return out
}

// webFrameworks lists import prefixes that mean "this file may register HTTP
// routes", per language.
var webFrameworks = map[language][][2]string{
	langGo: {
		{"github.com/gin-gonic/gin", "gin"},
		{"github.com/labstack/echo", "echo"},
		{"github.com/go-chi/chi", "chi"},
		{"github.com/gorilla/mux", "gorilla/mux"},
		{"github.com/gofiber/fiber", "fiber"},
		{"github.com/julienschmidt/httprouter", "httprouter"},
		{"github.com/valyala/fasthttp", "fasthttp"},
		{"github.com/beego/beego", "beego"},
		{"net/http", "net/http"},
	},
	langPython: {
		{"flask", "flask"},
		{"django", "django"},
		{"fastapi", "fastapi"},
		{"starlette", "starlette"},
		{"aiohttp", "aiohttp"},
		{"tornado", "tornado"},
		{"sanic", "sanic"},
		{"bottle", "bottle"},
		{"quart", "quart"},
		{"falcon", "falcon"},
	},
	langJS: {
		{"express", "express"},
		{"koa", "koa"},
		{"@koa", "koa"},
		{"fastify", "fastify"},
		{"@hapi", "hapi"},
		{"@nestjs", "nestjs"},
		{"next", "next"},
		{"restify", "restify"},
		{"polka", "polka"},
		{"hono", "hono"},
	},
}

// mailMIMEImports lists import prefixes that mean "this file parses or renders
// mail / MIME", per language.
var mailMIMEImports = map[language][]string{
	langGo: {
		"net/mail", "mime", "net/textproto", "net/smtp",
		"github.com/emersion/", "github.com/jhillyerd/enmime",
		"github.com/wneessen/go-mail", "github.com/xhit/go-simple-mail",
		"github.com/mnako/letters", "github.com/DusanKasan/parsemail",
	},
	langPython: {"email", "smtplib", "imaplib", "poplib", "mailbox", "aiosmtpd"},
	langJS:     {"nodemailer", "mailparser", "emailjs", "imap", "mailcomposer", "smtp-server"},
}

// webFrameworkFor reports whether an import means the file can register routes.
func webFrameworkFor(lang language, imp string) (string, bool) {
	for _, fw := range webFrameworks[lang] {
		if importMatches(imp, fw[0]) {
			return fw[1], true
		}
	}
	return "", false
}

// isMailMIMEImport reports whether an import means the file handles mail/MIME.
func isMailMIMEImport(lang language, imp string) bool {
	return matchesAny(imp, mailMIMEImports[lang])
}

// matchesAny reports whether an import matches any of the given prefixes.
func matchesAny(imp string, patterns []string) bool {
	for _, p := range patterns {
		if importMatches(imp, p) {
			return true
		}
	}
	return false
}

// importMatches compares an import against a prefix pattern on path-segment
// boundaries, so "mime" matches "mime/multipart" but not "mimetypes".
func importMatches(imp, pattern string) bool {
	imp = strings.ToLower(strings.Trim(imp, "./"))
	pattern = strings.ToLower(pattern)
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(imp, pattern)
	}
	if imp == pattern || strings.HasPrefix(imp, pattern+"/") {
		return true
	}
	// Python dotted modules: "email.parser" matches "email".
	return strings.HasPrefix(imp, pattern+".")
}

// isTestFile reports whether a path is a test file for its language. Test code
// is not deployed attack surface: a route registered in a fixture is not
// reachable in production and an assertion string is not an endpoint.
func isTestFile(path string, lang language) bool {
	norm := strings.ReplaceAll(path, "\\", "/")
	base := norm
	if i := strings.LastIndex(norm, "/"); i >= 0 {
		base = norm[i+1:]
	}
	switch lang {
	case langGo:
		return strings.HasSuffix(base, "_test.go")
	case langPython:
		return strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") ||
			base == "conftest.py" || strings.Contains(norm, "/tests/")
	case langJS:
		return reJSTestFile.MatchString(base) || strings.Contains(norm, "/__tests__/") ||
			strings.Contains(norm, "/__mocks__/") || strings.Contains(norm, "/cypress/")
	default:
		return false
	}
}

var reJSTestFile = regexp.MustCompile(`\.(?:test|spec)\.[cm]?[jt]sx?$`)

// --- endpoint extraction ---

var (
	// Go: any receiver chain calling a mux registration or a router verb. The
	// receiver is captured so header/parameter bags can be rejected, and the
	// path is validated separately — neither the call shape nor the framework
	// import alone is trusted.
	reGoHandle = regexp.MustCompile(`(?:^|[^\w.$])((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\.(HandleFunc|Handle)\s*\(\s*"((?:[^"\\]|\\.)*)"`)
	reGoVerb   = regexp.MustCompile(`(?:^|[^\w.$])((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any|Get|Post|Put|Delete|Patch|Head|Options|Route|Mount)\s*\(\s*"((?:[^"\\]|\\.)*)"`)

	// Python.
	rePyDecorator = regexp.MustCompile(`^\s*@\s*(?:[\w.]+\.)?(?:route|get|post|put|delete|patch|head|options|websocket)\s*\(\s*['"]([^'"]*)['"]`)
	rePyDjango    = regexp.MustCompile(`(?:^|[^\w.])(?:path|re_path|url)\s*\(\s*[rbu]?['"]([^'"]*)['"]`)

	// JavaScript / TypeScript.
	reJSRoute = regexp.MustCompile("(?:^|[^\\w.$])((?:[\\w$]+\\.)*[\\w$]+)\\.(get|post|put|delete|patch|all|head|options|use|ws)\\s*\\(\\s*['\"`]([^'\"`]*)['\"`]")
)

// nonRouterReceivers are identifiers that hold headers, form values or other
// key/value bags. `msg.Header.Get("Subject")` and `r.Header.Get("Authorization")`
// are header reads; they are never route registrations.
var nonRouterReceivers = map[string]bool{
	"header": true, "headers": true, "trailer": true, "trailers": true,
	"form": true, "postform": true, "values": true, "query": true,
	"params": true, "metadata": true, "meta": true, "cookies": true,
	"multipartform": true, "url": true, "env": true, "cache": true,
	"store": true, "config": true, "settings": true, "attrs": true,
	"labels": true, "annotations": true, "tags": true, "props": true,
	"flags": true, "opts": true, "options": true, "session": true,
	"context": true, "ctx": true, "state": true, "data": true, "fields": true,
}

// jsRouterNames are receiver names that are routers by convention, used when a
// JS file gives no usable import evidence (router modules often receive the
// router as a parameter).
var jsRouterNames = map[string]bool{
	"app": true, "router": true, "api": true, "server": true, "fastify": true,
	"express": true, "route": true, "routes": true, "sub": true, "instance": true,
}

// extractEndpoints returns the route paths registered on one line of code.
func extractEndpoints(codeLine string, facts fileFacts) []string {
	switch facts.lang {
	case langGo:
		return extractGoEndpoints(codeLine, facts)
	case langPython:
		return extractPyEndpoints(codeLine, facts)
	case langJS:
		return extractJSEndpoints(codeLine, facts)
	default:
		return nil
	}
}

// extractGoEndpoints requires net/http or a Go web framework in the file: a
// `.Get("x")` call in a file that imports neither is not a route.
func extractGoEndpoints(codeLine string, facts fileFacts) []string {
	if !facts.web {
		return nil
	}
	var out []string
	for _, re := range []*regexp.Regexp{reGoHandle, reGoVerb} {
		for _, m := range re.FindAllStringSubmatch(codeLine, -1) {
			if isNonRouterReceiver(m[1]) {
				continue
			}
			if p := unquoteGo(m[3]); looksLikeRoutePath(langGo, p) {
				out = appendUnique(out, p)
			}
		}
	}
	return out
}

// extractPyEndpoints handles Flask/FastAPI decorators and Django URLconfs; the
// Django form is gated on a django import because `path(...)` and `url(...)`
// are far too common to trust on their own.
func extractPyEndpoints(codeLine string, facts fileFacts) []string {
	if !facts.web {
		return nil
	}
	var out []string
	if m := rePyDecorator.FindStringSubmatch(codeLine); len(m) > 1 && looksLikeRoutePath(langPython, m[1]) {
		out = appendUnique(out, m[1])
	}
	if facts.framework == "django" {
		for _, m := range rePyDjango.FindAllStringSubmatch(codeLine, -1) {
			if looksLikeRoutePath(langPython, m[1]) {
				out = appendUnique(out, m[1])
			}
		}
	}
	return out
}

// extractJSEndpoints accepts either framework import evidence or a router-shaped
// receiver, because route modules commonly take the router as an argument.
func extractJSEndpoints(codeLine string, facts fileFacts) []string {
	var out []string
	for _, m := range reJSRoute.FindAllStringSubmatch(codeLine, -1) {
		recv := lastSegment(m[1])
		if isNonRouterReceiver(m[1]) {
			continue
		}
		if !facts.web && !jsRouterNames[strings.ToLower(recv)] {
			continue
		}
		if looksLikeRoutePath(langJS, m[3]) {
			out = appendUnique(out, m[3])
		}
	}
	return out
}

// isNonRouterReceiver reports whether the final segment of a receiver chain is a
// known header/parameter bag rather than a router.
func isNonRouterReceiver(recv string) bool {
	return nonRouterReceivers[strings.ToLower(lastSegment(recv))]
}

// lastSegment returns the final dotted segment of an identifier chain.
func lastSegment(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

// unquoteGo resolves the escape sequences that matter inside a route literal.
func unquoteGo(s string) string {
	return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(s)
}

// appendUnique appends v if it is not already present.
func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

// --- route path validation ---

var (
	// Go ServeMux patterns are "[METHOD ][HOST]/[PATH]"; a host must look like a
	// host (contain a dot), which is what keeps "multipart/mixed" out.
	reGoRoutePath = regexp.MustCompile(`^(?:[A-Z]{3,7}\s+)?(?:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)?/`)
	rePyRoutePath = regexp.MustCompile(`^[A-Za-z0-9_%.<>:{}()\[\]$^*+?\\|/-]+$`)
	reMediaType   = regexp.MustCompile(`(?i)^(?:text|image|audio|video|application|multipart|message|model|font|example)/[\w.+-]+$`)
)

// looksLikeRoutePath reports whether a string literal is shaped like an HTTP
// route path. A header name, a MIME media type or a prose fragment is not.
func looksLikeRoutePath(lang language, s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 512 {
		return false
	}
	if isHTTPHeaderName(s) || reMediaType.MatchString(s) {
		return false
	}
	switch lang {
	case langGo:
		return reGoRoutePath.MatchString(s) && !strings.Contains(strings.TrimPrefix(s, methodPrefix(s)), " ")
	case langPython:
		return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "^") || rePyRoutePath.MatchString(s)
	case langJS:
		return strings.HasPrefix(s, "/") || s == "*" || strings.HasPrefix(s, "*/")
	default:
		return false
	}
}

var reMethodPrefix = regexp.MustCompile(`^[A-Z]{3,7}\s+`)

// methodPrefix returns the leading "METHOD " of a Go 1.22 mux pattern, if any.
func methodPrefix(s string) string { return reMethodPrefix.FindString(s) }

// httpHeaderNames covers the HTTP and RFC 5322 / MIME header names that show up
// as string literals in header accessor calls. Reporting "Subject" or
// "Content-Type" as an endpoint is a category error, not a weak signal.
var httpHeaderNames = map[string]bool{
	"accept": true, "accept-charset": true, "accept-encoding": true,
	"accept-language": true, "accept-ranges": true, "age": true, "allow": true,
	"authorization": true, "bcc": true, "cache-control": true, "cc": true,
	"connection": true, "content-description": true, "content-disposition": true,
	"content-encoding": true, "content-id": true, "content-language": true,
	"content-length": true, "content-location": true, "content-md5": true,
	"content-range": true, "content-transfer-encoding": true, "content-type": true,
	"cookie": true, "date": true, "delivered-to": true, "dkim-signature": true,
	"etag": true, "expect": true, "expires": true, "from": true, "host": true,
	"if-match": true, "if-modified-since": true, "if-none-match": true,
	"if-range": true, "if-unmodified-since": true, "in-reply-to": true,
	"keep-alive": true, "last-modified": true, "list-id": true,
	"list-unsubscribe": true, "location": true, "message-id": true,
	"mime-version": true, "origin": true, "pragma": true, "precedence": true,
	"priority": true, "proxy-authenticate": true, "proxy-authorization": true,
	"range": true, "received": true, "references": true, "referer": true,
	"reply-to": true, "resent-date": true, "resent-from": true, "resent-to": true,
	"retry-after": true, "return-path": true, "sender": true, "server": true,
	"set-cookie": true, "strict-transport-security": true, "subject": true,
	"te": true, "to": true, "trailer": true, "transfer-encoding": true,
	"upgrade": true, "user-agent": true, "vary": true, "via": true,
	"warning": true, "www-authenticate": true,
}

// isHTTPHeaderName reports whether s names an HTTP/MIME header. Any `X-`
// prefixed token is treated as a header too, since extension headers are open
// ended and none of them are route paths.
func isHTTPHeaderName(s string) bool {
	if strings.ContainsAny(s, "/ \t") {
		return false
	}
	lower := strings.ToLower(s)
	return httpHeaderNames[lower] || strings.HasPrefix(lower, "x-")
}

// isCommonPublicEndpoint returns true for endpoints that are commonly public.
func isCommonPublicEndpoint(endpoint string) bool {
	public := []string{"/health", "/healthz", "/ready", "/readyz", "/ping", "/version", "/", "/favicon.ico", "/robots.txt"}
	lower := strings.ToLower(strings.TrimPrefix(endpoint, methodPrefix(endpoint)))
	for _, p := range public {
		if lower == p {
			return true
		}
	}
	return false
}

// --- upload / websocket matchers ---
//
// These run against code with comments removed *and* string literal contents
// blanked. The previous implementation matched bare keywords ("multipart",
// "upload") anywhere in the raw line, so a doc comment, an import path or a
// `strings.Contains(got, "multipart/mixed")` assertion all counted as file
// upload handling. Only HTTP form APIs count now: `mime/multipart` on its own is
// MIME composition, which mail code uses constantly.

var uploadPatterns = map[language]*regexp.Regexp{
	langGo:     regexp.MustCompile(`\.(?:FormFile|ParseMultipartForm|MultipartReader)\s*\(|\.MultipartForm\b`),
	langPython: regexp.MustCompile(`\brequest\.files\b|\bUploadFile\b|\b(?:File|Image)Field\s*\(|\bMultiPartParser\b|\brequest\.FILES\b`),
	langJS:     regexp.MustCompile(`\bmulter\s*\(|\bnew\s+Busboy\s*\(|\bbusboy\s*\(|\bformidable\s*\(|\breq\.files?\b|\bcreateWriteStream\s*\(\s*\)`),
}

var webSocketPatterns = map[language]*regexp.Regexp{
	langGo:     regexp.MustCompile(`\bwebsocket\.(?:Upgrader|Upgrade|Dial|NewClient)\b|\bUpgrader\{|\.Upgrade\s*\(|\bmelody\.New\s*\(`),
	langPython: regexp.MustCompile(`\bwebsockets?\.(?:serve|connect)\s*\(|\bWebSocketHandler\b|\bWebSocket\s*\(|@\w+\.websocket\b`),
	langJS:     regexp.MustCompile(`\bnew\s+WebSocket(?:\.Server)?\s*\(|\bnew\s+WebSocketServer\s*\(|\bsocketIO?\s*\(|@WebSocketGateway\b|\bio\.on\s*\(`),
}

// uploadLibs are dependencies whose whole purpose is receiving uploaded files.
// When one is imported, the middleware call shapes it hands out count too.
var uploadLibs = map[language][]string{
	langJS: {"multer", "busboy", "formidable", "connect-multiparty", "express-fileupload"},
}

// reUploadMiddleware matches multer/busboy style middleware application, which
// is only meaningful in a file that imports such a library.
var reUploadMiddleware = regexp.MustCompile(`\.(?:single|array|fields|any)\s*\(`)

// matchUpload returns the matched construct, or "" when the line does not handle
// an HTTP file upload.
func matchUpload(facts fileFacts, codeOnly string) string {
	if m := matchPattern(uploadPatterns[facts.lang], codeOnly); m != "" {
		return m
	}
	if facts.uploadLib {
		return matchPattern(reUploadMiddleware, codeOnly)
	}
	return ""
}

// isImportLine reports whether a line is an import statement. An import declares
// a dependency; the handling it enables lives elsewhere in the file.
func isImportLine(lang language, code string) bool {
	switch lang {
	case langPython:
		return rePyImportLine.MatchString(code)
	case langJS:
		return reJSImportLine.MatchString(code)
	default:
		return false
	}
}

var (
	rePyImportLine = regexp.MustCompile(`^\s*(?:from\s+[\w.]+\s+import\b|import\s+[\w.]+)`)
	reJSImportLine = regexp.MustCompile(`^\s*(?:import\b|export\s+\*|export\s+\{)`)
)

// matchWebSocket returns the matched construct, or "" when the line does not
// establish a WebSocket.
func matchWebSocket(lang language, codeOnly string) string {
	return matchPattern(webSocketPatterns[lang], codeOnly)
}

var (
	// A route whose path is a WebSocket path, e.g. "GET /ws" or "/api/socket".
	reWebSocketPath = regexp.MustCompile(`(?i)(?:^|/)(?:ws|wss|websocket|socket)(?:/|$)`)
	// A registration whose handler identifier names a WebSocket, e.g.
	// mux.HandleFunc("GET /ws", hub.HandleWebSocket).
	reWebSocketHandler = regexp.MustCompile(`(?i)[\w.]*websocket\w*\s*[,)]`)
)

// isWebSocketRoute reports whether a route registration establishes a WebSocket.
// It is scoped to lines that already yielded an endpoint, so a file full of
// WebSocket types does not produce a finding per line.
func isWebSocketRoute(endpoint, codeLine string) bool {
	return reWebSocketPath.MatchString(endpoint) || reWebSocketHandler.MatchString(codeLine)
}

func matchPattern(re *regexp.Regexp, s string) string {
	if re == nil {
		return ""
	}
	return strings.TrimSpace(re.FindString(s))
}
