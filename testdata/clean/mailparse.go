package clean

// Mail parsing, not web routing. Every string literal here is an RFC 5322 /
// MIME header name read through a header accessor; none of them is an endpoint.
// This file imports no web framework, so endpoint extraction must not run at all.

import (
	"mime"
	"net/mail"
	"strings"
)

// ParseHeaders reads the standard headers of a message.
func ParseHeaders(msg *mail.Message) map[string]string {
	out := map[string]string{}
	out["from"] = msg.Header.Get("From")
	out["to"] = msg.Header.Get("To")
	out["subject"] = msg.Header.Get("Subject")
	out["date"] = msg.Header.Get("Date")
	out["message_id"] = msg.Header.Get("Message-Id")
	out["reply_to"] = msg.Header.Get("Reply-To")
	return out
}

// MediaType reports the media type of a message body.
func MediaType(msg *mail.Message) string {
	ct, _, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}
	return strings.ToLower(ct)
}

// Encoding reports the transfer encoding of a message body.
func Encoding(msg *mail.Message) string {
	return msg.Header.Get("Content-Transfer-Encoding")
}
