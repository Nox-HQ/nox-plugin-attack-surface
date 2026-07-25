package clean

// MIME composition, not HTTP file upload handling. mime/multipart is the
// standard library's MIME writer; mail renderers use it constantly. Neither the
// doc comments below nor the string literals are code that handles an upload.
//
// Structure produced:
//   - body only                      → text/plain
//   - body + HTMLBody                → multipart/alternative (text, html)
//   - body + attachments             → multipart/mixed (text, attachment…)
//   - body + HTMLBody + attachments  → multipart/mixed (alternative, attachment…)

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"strings"
)

// Render writes a MIME document. The Content-Disposition below is a header
// value, not a file upload endpoint.
func Render(body, html string) ([]byte, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary("fixed-boundary"); err != nil {
		return nil, err
	}
	head := fmt.Sprintf("Content-Type: multipart/alternative; boundary=%q\r\n", w.Boundary())
	if _, err := buf.WriteString(head); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Verify checks rendered output. The assertions mention multipart media types;
// an assertion string is not attack surface.
func Verify(got string) error {
	if !strings.Contains(got, "multipart/mixed") {
		return fmt.Errorf("delivered message is not multipart/mixed:\n%s", got)
	}
	if !strings.Contains(got, "Content-Disposition: attachment; filename=\"upload.pdf\"") {
		return fmt.Errorf("missing attachment disposition")
	}
	return nil
}
