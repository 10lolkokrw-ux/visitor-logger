import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
)

# Render and similar hosts run behind one trusted reverse proxy.
# If deploying somewhere else, configure this for your actual proxy chain.
if os.environ.get("TRUST_PROXY", "1") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

DB_PATH = os.environ.get("DATABASE_PATH", "visitors.db")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "7"))

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                visited_at TEXT NOT NULL
            )
        """)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
        conn.execute("DELETE FROM visits WHERE visited_at < ?", (cutoff,))

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/consent")
def consent():
    if request.form.get("consent") != "yes":
        flash("Чтобы записать технические данные, необходимо согласие.")
        return redirect(url_for("index"))

    # The app stores only the IP and browser user-agent, after affirmative consent.
    ip = request.remote_addr or "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")[:500]
    visited_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with db() as conn:
        conn.execute(
            "INSERT INTO visits (ip, user_agent, visited_at) VALUES (?, ?, ?)",
            (ip[:64], user_agent, visited_at),
        )
    return render_template("thanks.html")

@app.get("/admin/login")
def login():
    return render_template("login.html")

@app.post("/admin/login")
def login_post():
    expected = os.environ.get("ADMIN_PASSWORD")
    if not expected:
        abort(503, "Set ADMIN_PASSWORD in your hosting environment.")
    if request.form.get("password", "") == expected:
        session.clear()
        session["admin"] = True
        return redirect(url_for("admin"))
    flash("Неверный пароль.")
    return redirect(url_for("login"))

@app.post("/admin/logout")
@admin_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/admin")
@admin_required
def admin():
    init_db()
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
        rows = conn.execute(
            "SELECT id, ip, user_agent, visited_at FROM visits ORDER BY id DESC LIMIT 200"
        ).fetchall()
    return render_template("admin.html", rows=rows, total=total, retention=RETENTION_DAYS)

@app.post("/admin/clear")
@admin_required
def clear():
    with db() as conn:
        conn.execute("DELETE FROM visits")
    flash("Журнал очищен.")
    return redirect(url_for("admin"))

@app.get("/health")
def health():
    return {"status": "ok"}

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
