package clean

// A test file full of MIME assertions. Two independent guards must keep this
// silent: test files are not attack surface, and even with include_tests the
// assertion strings are string data, not upload-handling code.

import (
	"mime"
	"net/mail"
	"strings"
	"testing"
)

func TestRenderedMessageIsMultipart(t *testing.T) {
	got := renderFixture()
	if !strings.Contains(got, "multipart/mixed") {
		t.Errorf("delivered message is not multipart/mixed:\n%s", got)
	}
	if !strings.Contains(got, "Content-Transfer-Encoding: base64") {
		t.Errorf("attachment is not base64 encoded")
	}
	if !strings.Contains(got, "Content-Disposition: attachment; filename=\"upload.pdf\"") {
		t.Errorf("missing upload.pdf attachment")
	}
}

func TestHeadersRoundTrip(t *testing.T) {
	msg := parseFixture(t)
	if msg.Header.Get("Subject") != "hello" {
		t.Errorf("Subject = %q", msg.Header.Get("Subject"))
	}
	if msg.Header.Get("From") == "" {
		t.Error("From header missing")
	}
	mt, _, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Errorf("media type = %q err = %v", mt, err)
	}
}

func renderFixture() string { return "" }

func parseFixture(t *testing.T) *mail.Message {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader("Subject: hello\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	return msg
}
