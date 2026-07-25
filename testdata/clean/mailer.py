"""Mail composition and parsing. No web framework, therefore no endpoints.

The header names below ("Subject", "To", "Content-Type") are RFC 5322 headers,
and multipart/alternative is a media type -- neither is an HTTP endpoint and
neither is file upload handling.
"""

import smtplib
from email import message_from_string
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def compose(subject, to, body, html=None):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to
    msg["From"] = "noreply@example.test"
    msg.attach(MIMEText(body, "plain"))
    if html:
        msg.attach(MIMEText(html, "html"))
    return msg


def read_headers(raw):
    msg = message_from_string(raw)
    return {
        "subject": msg.get("Subject"),
        "from": msg.get("From"),
        "content_type": msg.get("Content-Type"),
    }


def send(msg, host="localhost"):
    with smtplib.SMTP(host) as client:
        client.send_message(msg)
