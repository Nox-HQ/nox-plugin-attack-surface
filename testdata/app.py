"""A genuine Flask app: these routes must still be reported."""

from flask import Flask, request

app = Flask(__name__)


@app.route("/api/reports")
def reports():
    # request.headers.get("Authorization") is a header read, not a route.
    token = request.headers.get("Authorization")
    return {"token": bool(token)}


@app.post("/api/reports/upload")
def upload_report():
    f = request.files["document"]
    return {"name": f.filename}


@app.route("/admin/console")
def admin_console():
    return {"ok": True}


@app.route("/health")
def health():
    return "ok"
