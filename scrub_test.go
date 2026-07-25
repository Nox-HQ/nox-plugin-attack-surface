package main

import "testing"

func TestScrubRemovesComments(t *testing.T) {
	cases := []struct {
		name         string
		lang         language
		in           string
		wantCode     string
		wantCodeOnly string
	}{
		{"go line comment", langGo, `x := 1 // multipart/mixed upload`, `x := 1 `, `x := 1 `},
		{"go comment only", langGo, `// Attachments are files (multipart/mixed).`, ``, ``},
		{"go string kept in code", langGo, `http.HandleFunc("/api/users", h)`, `http.HandleFunc("/api/users", h)`, `http.HandleFunc("", h)`},
		{"go import path blanked", langGo, `	"mime/multipart"`, "\t\"mime/multipart\"", "\t\"\""},
		{"go url in string not a comment", langGo, `u := "http://example.com/x"`, `u := "http://example.com/x"`, `u := ""`},
		{"go raw string", langGo, "tag := `json:\"a\" doc:\"multipart/alternative\"`", "tag := `json:\"a\" doc:\"multipart/alternative\"`", "tag := ``"},
		{"python comment", langPython, `path("/x")  # upload here`, `path("/x")  `, `path("")  `},
		{"js line comment", langJS, `app.get('/a'); // multer(`, `app.get('/a'); `, `app.get(''); `},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scrubber{lang: tc.lang}
			code, codeOnly := s.scrub(tc.in)
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			if codeOnly != tc.wantCodeOnly {
				t.Errorf("codeOnly = %q, want %q", codeOnly, tc.wantCodeOnly)
			}
		})
	}
}

func TestScrubBlockCommentsSpanLines(t *testing.T) {
	lines := []string{
		`/* handleUpload uses r.FormFile("x")`,
		`   and multipart/form-data */`,
		`real := r.FormFile("doc")`,
	}
	_, codeOnly := scrubLines(langGo, lines)
	if matchUpload(fileFacts{lang: langGo}, codeOnly[0]) != "" || matchUpload(fileFacts{lang: langGo}, codeOnly[1]) != "" {
		t.Errorf("block comment leaked: %q %q", codeOnly[0], codeOnly[1])
	}
	if matchUpload(fileFacts{lang: langGo}, codeOnly[2]) == "" {
		t.Errorf("real upload missed after block comment: %q", codeOnly[2])
	}
}

func TestScrubRawStringsSpanLines(t *testing.T) {
	lines := []string{
		"const doc = `",
		`multipart/mixed with r.FormFile("x")`,
		"`",
		`f, _, _ := r.FormFile("doc")`,
	}
	_, codeOnly := scrubLines(langGo, lines)
	if matchUpload(fileFacts{lang: langGo}, codeOnly[1]) != "" {
		t.Errorf("raw string leaked: %q", codeOnly[1])
	}
	if matchUpload(fileFacts{lang: langGo}, codeOnly[3]) == "" {
		t.Errorf("real upload missed after raw string: %q", codeOnly[3])
	}
}

func TestScrubPythonTripleQuotes(t *testing.T) {
	lines := []string{
		`"""Docstring mentioning multipart/alternative and request.files.`,
		``,
		`More prose about UploadFile."""`,
		`f = request.files["doc"]`,
	}
	_, codeOnly := scrubLines(langPython, lines)
	for i := 0; i < 3; i++ {
		if matchUpload(fileFacts{lang: langPython}, codeOnly[i]) != "" {
			t.Errorf("docstring leaked at line %d: %q", i, codeOnly[i])
		}
	}
	if matchUpload(fileFacts{lang: langPython}, codeOnly[3]) == "" {
		t.Errorf("real upload missed after docstring: %q", codeOnly[3])
	}
}

func TestScrubHandlesEscapedQuotes(t *testing.T) {
	s := &scrubber{lang: langGo}
	code, codeOnly := s.scrub(`t.Errorf("not \"multipart/mixed\": %s", got)`)
	if code != `t.Errorf("not \"multipart/mixed\": %s", got)` {
		t.Errorf("code = %q", code)
	}
	if codeOnly != `t.Errorf("", got)` {
		t.Errorf("codeOnly = %q", codeOnly)
	}
}
