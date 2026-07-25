package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackDynamicRuntime)
}

func TestScanFindsHTTPEndpoints(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "ATTACK-001")
	if len(found) == 0 {
		t.Fatal("expected at least one ATTACK-001 (HTTP endpoint) finding")
	}
}

func TestScanFindsUnauthEndpoints(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "ATTACK-002")
	if len(found) == 0 {
		t.Fatal("expected at least one ATTACK-002 (unauthenticated endpoint) finding")
	}
}

func TestScanFindsAdminEndpoints(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "ATTACK-003")
	if len(found) == 0 {
		t.Fatal("expected at least one ATTACK-003 (admin/debug endpoint) finding")
	}
}

func TestScanFindsFileUpload(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "ATTACK-004")
	if len(found) == 0 {
		t.Fatal("expected at least one ATTACK-004 (file upload) finding")
	}
}

func TestScanFindsWebSocket(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "ATTACK-005")
	if len(found) == 0 {
		t.Fatal("expected at least one ATTACK-005 (WebSocket) finding")
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)
	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings, got %d", len(resp.GetFindings()))
	}
}

// --- false positive regressions ---
//
// These cover the shapes that made the plugin fire 67 times on a Go mail server
// with no HTTP routing: mail header reads read as endpoints, and MIME prose and
// assertions read as file upload handling.

// TestNoHeaderNamesAsEndpoints guards rule 1: a well-known HTTP/MIME header name
// is never an endpoint, including inside files that do serve HTTP.
func TestNoHeaderNamesAsEndpoints(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	for _, f := range resp.GetFindings() {
		ep := f.GetMetadata()["endpoint"]
		if ep == "" {
			continue
		}
		if isHTTPHeaderName(ep) {
			t.Errorf("%s reported header %q as an endpoint at %s:%d",
				f.GetRuleId(), ep, f.GetLocation().GetFilePath(), f.GetLocation().GetStartLine())
		}
	}
}

// TestMailParsingHasNoEndpoints guards rule 2: a file that parses mail with
// net/mail and imports no web framework has no HTTP attack surface.
func TestMailParsingHasNoEndpoints(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "clean"))

	if n := len(resp.GetFindings()); n != 0 {
		for _, f := range resp.GetFindings() {
			t.Logf("unexpected %s at %s:%d: %s", f.GetRuleId(),
				f.GetLocation().GetFilePath(), f.GetLocation().GetStartLine(), f.GetMessage())
		}
		t.Fatalf("expected 0 findings in mail/MIME code, got %d", n)
	}
}

// TestMIMEProseIsNotFileUpload guards rule 4: the upload matcher must key off
// HTTP form APIs, not off the word "multipart" appearing in a comment, an
// import path or a test assertion. Test files are included here so the matcher
// itself is under test, not the test-file policy.
func TestMIMEProseIsNotFileUpload(t *testing.T) {
	client := testClient(t)
	resp := invokeScanWithInput(t, client, map[string]any{
		"workspace_root": filepath.Join(testdataDir(t), "clean"),
		"include_tests":  true,
	})

	if found := findByRule(resp.GetFindings(), "ATTACK-004"); len(found) != 0 {
		for _, f := range found {
			t.Logf("unexpected upload finding at %s:%d: %s",
				f.GetLocation().GetFilePath(), f.GetLocation().GetStartLine(), f.GetMessage())
		}
		t.Fatalf("expected 0 ATTACK-004 in MIME/mail code, got %d", len(found))
	}
}

// TestTestFilesAreSkippedByDefault guards rule 3: a route registered in a test
// fixture is not deployed attack surface.
func TestTestFilesAreSkippedByDefault(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "testonly"))

	if n := len(resp.GetFindings()); n != 0 {
		t.Fatalf("expected 0 findings in test files, got %d", n)
	}
}

// TestIncludeTestsOptIn documents the escape hatch for the policy above.
func TestIncludeTestsOptIn(t *testing.T) {
	client := testClient(t)
	resp := invokeScanWithInput(t, client, map[string]any{
		"workspace_root": filepath.Join(testdataDir(t), "testonly"),
		"include_tests":  true,
	})

	if !hasEndpoint(resp.GetFindings(), "ATTACK-001", "/fixture/token") {
		t.Fatal("expected the fixture route once include_tests is set")
	}
}

// --- true positive regressions ---

// TestGenuineUnauthEndpointStillFires is the recall guard: a real net/http
// server with a registered route and no auth middleware must still be reported.
func TestGenuineUnauthEndpointStillFires(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	for _, want := range []string{"/api/users", "/api/orders"} {
		if !hasEndpoint(resp.GetFindings(), "ATTACK-001", want) {
			t.Errorf("lost ATTACK-001 for %s", want)
		}
		if !hasEndpoint(resp.GetFindings(), "ATTACK-002", want) {
			t.Errorf("lost ATTACK-002 for %s", want)
		}
	}
}

// TestFrameworkRoutesStillFire covers the framework extractors: a Go 1.22 mux
// pattern, a chi router and a Flask decorator.
func TestFrameworkRoutesStillFire(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	for _, want := range []string{
		"POST /api/session",   // net/http, Go 1.22 method pattern
		"/api/things",         // chi
		"/api/reports",        // flask
		"/api/products",       // express
		"/api/reports/upload", // flask, POST decorator
	} {
		if !hasEndpoint(resp.GetFindings(), "ATTACK-001", want) {
			t.Errorf("lost ATTACK-001 for %s", want)
		}
	}
}

// --- helpers ---

// hasEndpoint reports whether a finding of ruleID carries the given endpoint.
func hasEndpoint(findings []*pluginv1.Finding, ruleID, endpoint string) bool {
	for _, f := range findByRule(findings, ruleID) {
		if f.GetMetadata()["endpoint"] == endpoint {
			return true
		}
	}
	return false
}

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	return invokeScanWithInput(t, client, map[string]any{"workspace_root": workspaceRoot})
}

func invokeScanWithInput(t *testing.T, client pluginv1.PluginServiceClient, in map[string]any) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(in)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}

func cleanDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata", "clean")
}

// TestCleanCodeNoEndpoints is the FP guard: non-server code (no routes/handlers)
// must surface zero endpoints — guards against matching arbitrary code as an
// attack-surface entry point.
func TestCleanCodeNoEndpoints(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, cleanDir(t))
	if n := len(resp.GetFindings()); n != 0 {
		for _, f := range resp.GetFindings() {
			t.Logf("unexpected endpoint: %s at line %d", f.GetRuleId(), f.GetLocation().GetStartLine())
		}
		t.Fatalf("expected 0 endpoints in clean code, got %d", n)
	}
}
