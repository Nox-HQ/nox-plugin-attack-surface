package main

import (
	"strings"
	"testing"
)

// --- route path validation ---

func TestLooksLikeRoutePath(t *testing.T) {
	cases := []struct {
		name string
		lang language
		in   string
		want bool
	}{
		{"go absolute path", langGo, "/api/users", true},
		{"go mux method pattern", langGo, "GET /items/{id}", true},
		{"go host pattern", langGo, "example.com/static/", true},
		{"go root", langGo, "/", true},
		{"mail header From", langGo, "From", false},
		{"mail header Subject", langGo, "Subject", false},
		{"mail header Message-Id", langGo, "Message-Id", false},
		{"mime header Content-Type", langGo, "Content-Type", false},
		{"mime header Content-Disposition", langGo, "Content-Disposition", false},
		{"mime header Content-Transfer-Encoding", langGo, "Content-Transfer-Encoding", false},
		{"http header Authorization", langGo, "Authorization", false},
		{"extension header", langGo, "X-Request-Id", false},
		{"media type", langGo, "multipart/mixed", false},
		{"media type alternative", langGo, "multipart/alternative", false},
		{"media type text", langGo, "text/html", false},
		{"prose", langGo, "delivered message is not multipart", false},
		{"empty", langGo, "", false},
		{"python absolute", langPython, "/api/reports", true},
		{"python django relative", langPython, "api/v1/orders/", true},
		{"python regex", langPython, "^articles/(?P<year>[0-9]{4})/$", true},
		{"python header name", langPython, "Subject", false},
		{"python header content type", langPython, "Content-Type", false},
		{"js absolute", langJS, "/api/products", true},
		{"js wildcard", langJS, "*", true},
		{"js header name", langJS, "Content-Type", false},
		{"js bare word", langJS, "json", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeRoutePath(tc.lang, tc.in); got != tc.want {
				t.Errorf("looksLikeRoutePath(%s, %q) = %v, want %v", tc.lang, tc.in, got, tc.want)
			}
		})
	}
}

func TestIsHTTPHeaderName(t *testing.T) {
	headers := []string{"Subject", "From", "To", "Date", "Message-Id", "Content-Type",
		"Content-Disposition", "Content-Transfer-Encoding", "Authorization", "X-Custom-Thing"}
	for _, h := range headers {
		if !isHTTPHeaderName(h) {
			t.Errorf("isHTTPHeaderName(%q) = false, want true", h)
		}
	}
	for _, p := range []string{"/api/users", "/from", "multipart/mixed", "api/date"} {
		if isHTTPHeaderName(p) {
			t.Errorf("isHTTPHeaderName(%q) = true, want false", p)
		}
	}
}

// --- endpoint extraction ---

func TestExtractEndpointsRejectsHeaderAccess(t *testing.T) {
	// A web file: extraction is enabled, so only the path shape and receiver
	// checks stand between a header read and a bogus endpoint.
	facts := fileFacts{lang: langGo, web: true, framework: "chi"}
	lines := []string{
		`out["subject"] = decode(msg.Header.Get("Subject"))`,
		`out["date"] = msg.Header.Get("Date")`,
		`if v := r.Header.Get("Authorization"); v != "" {`,
		`ct, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))`,
		`disp, dparams, err := mime.ParseMediaType(att.Header.Get("Content-Disposition"))`,
	}
	for _, line := range lines {
		if got := extractEndpoints(line, facts); len(got) != 0 {
			t.Errorf("extractEndpoints(%q) = %v, want none", line, got)
		}
	}
}

func TestExtractEndpointsFindsRealRoutes(t *testing.T) {
	cases := []struct {
		name  string
		facts fileFacts
		line  string
		want  string
	}{
		{"net/http HandleFunc", fileFacts{lang: langGo, web: true}, `http.HandleFunc("/api/users", handleUsers)`, "/api/users"},
		{"mux var HandleFunc", fileFacts{lang: langGo, web: true}, `mux.HandleFunc("/admin/dashboard", h)`, "/admin/dashboard"},
		{"nested receiver", fileFacts{lang: langGo, web: true}, `s.mux.HandleFunc("/api/orders", h)`, "/api/orders"},
		{"go 1.22 pattern", fileFacts{lang: langGo, web: true}, `mux.HandleFunc("GET /api/status/{id}", h)`, "GET /api/status/{id}"},
		{"chi", fileFacts{lang: langGo, web: true, framework: "chi"}, `r.Get("/api/things", listThings)`, "/api/things"},
		{"gin", fileFacts{lang: langGo, web: true, framework: "gin"}, `router.POST("/api/login", login)`, "/api/login"},
		{"echo", fileFacts{lang: langGo, web: true, framework: "echo"}, `e.GET("/api/ping", ping)`, "/api/ping"},
		{"flask", fileFacts{lang: langPython, web: true, framework: "flask"}, `@app.route("/api/reports")`, "/api/reports"},
		{"fastapi", fileFacts{lang: langPython, web: true, framework: "fastapi"}, `@router.get("/api/items")`, "/api/items"},
		{"django", fileFacts{lang: langPython, web: true, framework: "django"}, `path("api/v1/orders/", views.orders),`, "api/v1/orders/"},
		{"express", fileFacts{lang: langJS, web: true, framework: "express"}, `app.get('/api/products', handler);`, "/api/products"},
		{"router param", fileFacts{lang: langJS}, `router.post('/api/checkout', handler);`, "/api/checkout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractEndpoints(tc.line, tc.facts)
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("extractEndpoints(%q) = %v, want [%q]", tc.line, got, tc.want)
			}
		})
	}
}

func TestExtractEndpointsRequiresWebImport(t *testing.T) {
	// Same call shapes, but the file imports no web framework.
	facts := fileFacts{lang: langGo}
	lines := []string{
		`r.Get("/api/things", listThings)`,
		`mux.HandleFunc("/api/users", handleUsers)`,
	}
	for _, line := range lines {
		if got := extractEndpoints(line, facts); len(got) != 0 {
			t.Errorf("extractEndpoints(%q) without web imports = %v, want none", line, got)
		}
	}
}

func TestExtractEndpointsRejectsNonRouterReceivers(t *testing.T) {
	facts := fileFacts{lang: langJS, web: true, framework: "express"}
	for _, line := range []string{
		`const cached = cache.get('/api/products');`,
		`const v = headers.get('/weird');`,
	} {
		if got := extractEndpoints(line, facts); len(got) != 0 {
			t.Errorf("extractEndpoints(%q) = %v, want none", line, got)
		}
	}
}

// --- upload matcher ---

func TestMatchUploadIgnoresCommentsAndStrings(t *testing.T) {
	// These are the shapes the matcher used to fire on. They are fed through
	// the scrubber exactly as the scanner does.
	lines := []string{
		`// Attachments are files delivered with the message (multipart/mixed).`,
		`//   - body + HTMLBody               → multipart/alternative (text, html)`,
		`if !strings.Contains(got, "multipart/mixed") {`,
		`t.Errorf("delivered message is not multipart/mixed:\n%s", got)`,
		`"mime/multipart"`,
		"HTMLBody string `json:\"html_body\" jsonschema:\"description=sent as multipart/alternative\"`",
		`w := multipart.NewWriter(&buf)`,
		`msg.Header.Get("Content-Disposition")`,
	}
	_, codeOnly := scrubLines(langGo, lines)
	for i, line := range lines {
		if m := matchUpload(fileFacts{lang: langGo}, codeOnly[i]); m != "" {
			t.Errorf("matchUpload fired on %q (scrubbed %q) with %q", line, codeOnly[i], m)
		}
	}
}

func TestMatchUploadFindsRealUploads(t *testing.T) {
	cases := []struct {
		lang language
		line string
	}{
		{langGo, `file, hdr, err := r.FormFile("document")`},
		{langGo, `if err := r.ParseMultipartForm(32 << 20); err != nil {`},
		{langGo, `mr, err := r.MultipartReader()`},
		{langPython, `f = request.files["document"]`},
		{langPython, `async def upload(file: UploadFile = File(...)):`},
		{langJS, `const upload = multer({ dest: 'uploads/' });`},
		{langJS, `const form = formidable({ multiples: true });`},
	}
	for _, tc := range cases {
		_, codeOnly := scrubLines(tc.lang, []string{tc.line})
		if m := matchUpload(fileFacts{lang: tc.lang}, codeOnly[0]); m == "" {
			t.Errorf("matchUpload(%s, %q) found nothing", tc.lang, tc.line)
		}
	}
}

func TestMatchUploadMiddlewareNeedsUploadLib(t *testing.T) {
	line := `app.post('/api/import', upload.single('file'), handler);`
	_, codeOnly := scrubLines(langJS, []string{line})

	if m := matchUpload(fileFacts{lang: langJS}, codeOnly[0]); m != "" {
		t.Errorf("upload middleware matched without an upload library: %q", m)
	}
	if m := matchUpload(fileFacts{lang: langJS, uploadLib: true}, codeOnly[0]); m == "" {
		t.Error("upload middleware missed in a file that imports multer")
	}
}

func TestImportLinesAreNotHandlingCode(t *testing.T) {
	cases := []struct {
		lang language
		line string
		want bool
	}{
		{langPython, `from fastapi import FastAPI, UploadFile, File`, true},
		{langPython, `import smtplib`, true},
		{langPython, `f = request.files["doc"]`, false},
		{langJS, `import multer from 'multer';`, true},
		{langJS, `const upload = multer({ dest: 'uploads/' });`, false},
	}
	for _, tc := range cases {
		if got := isImportLine(tc.lang, tc.line); got != tc.want {
			t.Errorf("isImportLine(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// --- websocket matcher ---

func TestMatchWebSocketIgnoresProse(t *testing.T) {
	lines := []string{
		`// Server is the dashboard HTTP server with REST API and WebSocket support.`,
		`// WebSocket`,
		`"github.com/gorilla/websocket"`,
		`t.Skipf("websocket dial not available: %v", err)`,
	}
	_, codeOnly := scrubLines(langGo, lines)
	for i, line := range lines {
		if m := matchWebSocket(langGo, codeOnly[i]); m != "" {
			t.Errorf("matchWebSocket fired on %q with %q", line, m)
		}
	}
}

func TestMatchWebSocketFindsUpgrades(t *testing.T) {
	cases := []struct {
		lang language
		line string
	}{
		{langGo, `var upgrader = websocket.Upgrader{ReadBufferSize: 1024}`},
		{langGo, `conn, err := upgrader.Upgrade(w, r, nil)`},
		{langJS, `const wss = new WebSocket.Server({ port: 8080 });`},
	}
	for _, tc := range cases {
		_, codeOnly := scrubLines(tc.lang, []string{tc.line})
		if m := matchWebSocket(tc.lang, codeOnly[0]); m == "" {
			t.Errorf("matchWebSocket(%s, %q) found nothing", tc.lang, tc.line)
		}
	}
}

func TestIsWebSocketRoute(t *testing.T) {
	if !isWebSocketRoute("GET /ws", `mux.HandleFunc("GET /ws", hub.HandleWebSocket)`) {
		t.Error("expected a /ws route to be a WebSocket endpoint")
	}
	if isWebSocketRoute("/api/users", `mux.HandleFunc("/api/users", handleUsers)`) {
		t.Error("plain route reported as WebSocket")
	}
}

// --- file classification ---

func TestIsTestFile(t *testing.T) {
	cases := []struct {
		path string
		lang language
		want bool
	}{
		{"domain/render_test.go", langGo, true},
		{"domain/render.go", langGo, false},
		{"cmd/testify/helper.go", langGo, false},
		{"api/test_views.py", langPython, true},
		{"api/views_test.py", langPython, true},
		{"api/conftest.py", langPython, true},
		{"api/views.py", langPython, false},
		{"src/app.test.ts", langJS, true},
		{"src/app.spec.jsx", langJS, true},
		{"src/__tests__/app.js", langJS, true},
		{"src/app.js", langJS, false},
	}
	for _, tc := range cases {
		if got := isTestFile(tc.path, tc.lang); got != tc.want {
			t.Errorf("isTestFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestGatherFactsSuppressesMailOnlyFiles(t *testing.T) {
	src := []string{
		`package mail`,
		`import (`,
		`	"mime"`,
		`	"net/mail"`,
		`)`,
		`func f(msg *mail.Message) string { return msg.Header.Get("Subject") }`,
	}
	code, _ := scrubLines(langGo, src)
	facts := gatherFacts("infrastructure/parse.go", langGo, code)
	if !facts.mailMIME {
		t.Fatalf("expected mailMIME, imports = %v", facts.imports)
	}
	if facts.web {
		t.Fatal("expected no web imports")
	}
	if !facts.routingSuppressed() {
		t.Fatal("expected routing to be suppressed for a mail-only file")
	}
}

func TestGatherFactsKeepsMixedMailAndWebFiles(t *testing.T) {
	src := []string{
		`import (`,
		`	"net/http"`,
		`	"net/mail"`,
		`)`,
	}
	code, _ := scrubLines(langGo, src)
	facts := gatherFacts("webmail/handler.go", langGo, code)
	if !facts.web || !facts.mailMIME {
		t.Fatalf("want web+mail, got web=%v mail=%v", facts.web, facts.mailMIME)
	}
	if facts.routingSuppressed() {
		t.Fatal("a file that imports net/http still routes")
	}
}

// --- end-to-end over source text ---

func TestAnalyzeSourceMailParsingProducesNothing(t *testing.T) {
	src := strings.Split(`package mcpserver

import (
	"mime"
	"net/mail"
)

func parseHeaders(msg *mail.Message) map[string]string {
	out := map[string]string{}
	out["from"] = msg.Header.Get("From")
	out["to"] = msg.Header.Get("To")
	out["subject"] = msg.Header.Get("Subject")
	out["date"] = msg.Header.Get("Date")
	out["message_id"] = msg.Header.Get("Message-Id")
	return out
}`, "\n")

	got := analyzeSource("infrastructure/mcpserver/resources.go", langGo, src)
	if len(got.findings) != 0 {
		t.Fatalf("expected no findings for mail parsing, got %d: %+v", len(got.findings), got.findings)
	}
}

func TestAnalyzeSourceKeepsUnauthenticatedRoute(t *testing.T) {
	src := strings.Split(`package api

import "net/http"

func Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/orders", handleOrders)
}`, "\n")

	got := analyzeSource("api/routes.go", langGo, src)
	var endpoint, unauth bool
	for _, f := range got.findings {
		if f.rule == ruleEndpoint && f.endpoint == "/api/orders" {
			endpoint = true
		}
		if f.rule == ruleUnauth && f.endpoint == "/api/orders" {
			unauth = true
		}
	}
	if !endpoint || !unauth {
		t.Fatalf("expected endpoint+unauth findings, got %+v", got.findings)
	}
}
