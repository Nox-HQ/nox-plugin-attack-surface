package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// --- Compiled regex patterns ---

var (
	// Go HTTP endpoints.
	reGoHTTPHandle   = regexp.MustCompile(`(?:http\.HandleFunc|http\.Handle|mux\.HandleFunc|mux\.Handle|r\.HandleFunc|r\.Handle)\s*\(\s*["']([^"']+)["']`)
	reGoGinRoute     = regexp.MustCompile(`(?:r|router|g|group|e|engine)\.\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\(\s*["']([^"']+)["']`)
	reGoEchoRoute    = regexp.MustCompile(`(?:e|echo)\.\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["']([^"']+)["']`)
	reGoChiRoute     = regexp.MustCompile(`(?:r|router)\.\s*(Get|Post|Put|Delete|Patch|Head|Options|Route)\s*\(\s*["']([^"']+)["']`)

	// Python HTTP endpoints.
	rePyFlask   = regexp.MustCompile(`@(?:app|blueprint|bp)\.\s*(?:route|get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	rePyDjango  = regexp.MustCompile(`(?:path|re_path|url)\s*\(\s*["']([^"']+)["']`)
	rePyFastAPI = regexp.MustCompile(`@(?:app|router)\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*["']([^"']+)["']`)

	// JavaScript/TypeScript HTTP endpoints.
	reJSExpress = regexp.MustCompile(`(?:app|router)\.\s*(get|post|put|delete|patch|all|use)\s*\(\s*['"]([^'"]+)['"]`)
	reJSKoa     = regexp.MustCompile(`(?:router)\.\s*(get|post|put|delete|patch|all)\s*\(\s*['"]([^'"]+)['"]`)
	reJSFastify = regexp.MustCompile(`(?:fastify|server|app)\.\s*(get|post|put|delete|patch|all|route)\s*\(\s*['"]([^'"]+)['"]`)

	// Auth middleware patterns.
	reAuthMiddleware = regexp.MustCompile(`(?i)(auth.?middleware|requireAuth|isAuthenticated|authenticate|jwt.?middleware|passport\.|@login_required|@requires_auth|AuthGuard|UseGuards|Depends\(.*auth)`)

	// Admin/debug endpoints.
	reAdminDebug = regexp.MustCompile(`(?i)(/admin|/debug|/metrics|/health|/status|/internal|/actuator|/__debug__|/pprof|/swagger|/graphql|/playground)`)

	// File upload handling.
	reFileUpload = regexp.MustCompile(`(?i)(multipart|FormFile|upload|multer|FileField|UploadFile|busboy|formidable)`)

	// WebSocket endpoints.
	reWebSocket = regexp.MustCompile(`(?i)(websocket|ws://|wss://|Upgrader|socket\.io|@WebSocket|@SubscribeMessage|\.ws\(|\.websocket\()`)
)

// sourceExtensions lists file extensions to scan.
var sourceExtensions = map[string]bool{
	".go":  true,
	".py":  true,
	".js":  true,
	".ts":  true,
	".jsx": true,
	".tsx": true,
}

// skippedDirs to skip during walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
	"dist":         true,
	"build":        true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/attack-surface", version).
		Capability("attack-surface", "Static endpoint extraction and attack surface inventory").
		Tool("scan", "Extract HTTP endpoints, detect unauthenticated routes, admin/debug exposure, file uploads, and WebSocket endpoints", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !sourceExtensions[ext] {
			return nil
		}

		return scanFileForEndpoints(resp, path, ext)
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

// scanFileForEndpoints extracts endpoints and checks for attack surface issues.
func scanFileForEndpoints(resp *sdk.ResponseBuilder, filePath, ext string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0

	// Track auth middleware per file.
	hasAuthInFile := false
	var lines []string

	// First pass: read all lines and check for auth middleware.
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
		if reAuthMiddleware.MatchString(line) {
			hasAuthInFile = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Second pass: find endpoints.
	for i, line := range lines {
		lineNum = i + 1

		endpoint := extractEndpoint(line, ext)
		if endpoint != "" {
			// ATTACK-001: HTTP endpoint detected.
			resp.Finding(
				"ATTACK-001",
				sdk.SeverityInfo,
				sdk.ConfidenceHigh,
				fmt.Sprintf("HTTP endpoint detected: %s", endpoint),
			).
				At(filePath, lineNum, lineNum).
				WithMetadata("endpoint", endpoint).
				Done()

			// ATTACK-002: Check if endpoint lacks auth.
			if !hasAuthInFile && !isCommonPublicEndpoint(endpoint) {
				resp.Finding(
					"ATTACK-002",
					sdk.SeverityMedium,
					sdk.ConfidenceMedium,
					fmt.Sprintf("Potentially unauthenticated endpoint: %s", endpoint),
				).
					At(filePath, lineNum, lineNum).
					WithMetadata("endpoint", endpoint).
					Done()
			}

			// ATTACK-003: Admin/debug endpoint.
			if reAdminDebug.MatchString(endpoint) {
				resp.Finding(
					"ATTACK-003",
					sdk.SeverityMedium,
					sdk.ConfidenceHigh,
					fmt.Sprintf("Admin/debug endpoint exposed: %s", endpoint),
				).
					At(filePath, lineNum, lineNum).
					WithMetadata("endpoint", endpoint).
					Done()
			}
		}

		// ATTACK-004: File upload handling.
		if reFileUpload.MatchString(line) {
			resp.Finding(
				"ATTACK-004",
				sdk.SeverityLow,
				sdk.ConfidenceMedium,
				fmt.Sprintf("File upload handling detected: %s", strings.TrimSpace(line)),
			).
				At(filePath, lineNum, lineNum).
				Done()
		}

		// ATTACK-005: WebSocket endpoint.
		if reWebSocket.MatchString(line) {
			resp.Finding(
				"ATTACK-005",
				sdk.SeverityMedium,
				sdk.ConfidenceMedium,
				fmt.Sprintf("WebSocket endpoint detected: %s", strings.TrimSpace(line)),
			).
				At(filePath, lineNum, lineNum).
				Done()
		}
	}

	return nil
}

// extractEndpoint tries to extract an HTTP endpoint path from a line.
func extractEndpoint(line, ext string) string {
	switch ext {
	case ".go":
		if m := reGoHTTPHandle.FindStringSubmatch(line); len(m) > 1 {
			return m[1]
		}
		if m := reGoGinRoute.FindStringSubmatch(line); len(m) > 2 {
			return m[2]
		}
		if m := reGoEchoRoute.FindStringSubmatch(line); len(m) > 2 {
			return m[2]
		}
		if m := reGoChiRoute.FindStringSubmatch(line); len(m) > 2 {
			return m[2]
		}
	case ".py":
		if m := rePyFlask.FindStringSubmatch(line); len(m) > 1 {
			return m[1]
		}
		if m := rePyDjango.FindStringSubmatch(line); len(m) > 1 {
			return m[1]
		}
		if m := rePyFastAPI.FindStringSubmatch(line); len(m) > 1 {
			return m[1]
		}
	case ".js", ".ts", ".jsx", ".tsx":
		if m := reJSExpress.FindStringSubmatch(line); len(m) > 2 {
			return m[2]
		}
		if m := reJSKoa.FindStringSubmatch(line); len(m) > 2 {
			return m[2]
		}
		if m := reJSFastify.FindStringSubmatch(line); len(m) > 2 {
			return m[2]
		}
	}
	return ""
}

// isCommonPublicEndpoint returns true for endpoints that are commonly public.
func isCommonPublicEndpoint(endpoint string) bool {
	public := []string{"/health", "/healthz", "/ready", "/readyz", "/ping", "/version", "/", "/favicon.ico", "/robots.txt"}
	lower := strings.ToLower(endpoint)
	for _, p := range public {
		if lower == p {
			return true
		}
	}
	return false
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-attack-surface: %v\n", err)
		os.Exit(1)
	}
}
