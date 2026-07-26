package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

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

// maxFileBytes caps the size of a file the scanner will read; generated bundles
// and fixtures above this are not hand-written attack surface.
const maxFileBytes = 4 << 20

// maxLineBytes is the longest single line bufio.Scanner will accept.
const maxLineBytes = 1 << 20

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
	includeTests := boolInput(req.Input["include_tests"])

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

		lang := languageFor(filepath.Ext(path))
		if lang == langUnknown {
			return nil
		}
		return scanFile(resp, path, lang, includeTests)
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

// boolInput coerces a tool input value that may arrive as a bool or a string.
func boolInput(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true") || t == "1"
	default:
		return false
	}
}

// scanFile analyses one source file and emits its findings.
func scanFile(resp *sdk.ResponseBuilder, path string, lang language, includeTests bool) error {
	if !includeTests && isTestFile(path, lang) {
		return nil
	}
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	if lines == nil {
		return nil
	}

	for _, f := range analyzeSource(path, lang, lines).findings {
		emitFinding(resp, path, f)
	}
	return nil
}

// readLines reads a source file, returning nil for files that are unreadable or
// too large to be hand-written source.
func readLines(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxFileBytes {
		return nil, nil //nolint:nilerr // unreadable or oversized files are skipped, not fatal
	}
	f, err := os.Open(path) //nolint:gosec // scanning caller-supplied workspace paths is the plugin's job
	if err != nil {
		return nil, nil //nolint:nilerr // an unreadable file is not a scan failure
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, nil //nolint:nilerr // truncated or binary files are skipped, not fatal
	}
	return lines, nil
}

// emitFinding maps an analysis result onto the SDK finding model.
func emitFinding(resp *sdk.ResponseBuilder, path string, f rawFinding) {
	severity, confidence, message := describe(f)

	fb := resp.Finding(f.rule, severity, confidence, message).
		At(path, f.line, f.line)
	if f.endpoint != "" {
		fb = fb.WithMetadata("endpoint", f.endpoint)
	}
	if f.framework != "" {
		fb = fb.WithMetadata("framework", f.framework)
	}
	fb.Done()
}

// describe returns the severity, confidence and message for a finding.
func describe(f rawFinding) (pluginv1.Severity, pluginv1.Confidence, string) {
	switch f.rule {
	case ruleEndpoint:
		return sdk.SeverityInfo, sdk.ConfidenceHigh,
			fmt.Sprintf("HTTP endpoint detected: %s", f.endpoint)
	case ruleUnauth:
		return sdk.SeverityMedium, sdk.ConfidenceMedium,
			fmt.Sprintf("Potentially unauthenticated endpoint: %s", f.endpoint)
	case ruleAdminDebug:
		return sdk.SeverityMedium, sdk.ConfidenceHigh,
			fmt.Sprintf("Admin/debug endpoint exposed: %s", f.endpoint)
	case ruleUpload:
		return sdk.SeverityLow, sdk.ConfidenceMedium,
			fmt.Sprintf("File upload handling detected: %s", f.evidence)
	case ruleWebSocket:
		return sdk.SeverityMedium, sdk.ConfidenceMedium,
			fmt.Sprintf("WebSocket endpoint detected: %s", f.evidence)
	default:
		return sdk.SeverityInfo, sdk.ConfidenceLow, f.rule
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-attack-surface: %v\n", err)
		return 1
	}
	return 0
}
