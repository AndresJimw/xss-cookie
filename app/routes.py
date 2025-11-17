from __future__ import annotations

from flask import (
    Blueprint,
    Flask,
    redirect,
    render_template,
    request,
    url_for,
)

from . import storage
from . import security

bp = Blueprint("main", __name__)

def init_app(app: Flask) -> None:
    """Registra el blueprint y el hook after_request."""
    app.register_blueprint(bp)

    @app.after_request
    def _apply_security_headers(response):
        return security.apply_security_headers(response)

@bp.route("/")
def index():
    """Página inicial del lab."""
    security_mode = security.get_security_mode()
    return render_template("index.html", security_mode=security_mode)

@bp.route("/search")
def search():
    """Escenario de XSS reflejado: GET /search?q=..."""
    query = request.args.get("q", "")

    raw_output = query
    safe_output = security.secure_output(query, context="text")

    return render_template(
        "search.html",
        query=query,
        raw_output=raw_output,
        safe_output=safe_output,
        security_mode=security.get_security_mode(),
    )

@bp.route("/comments", methods=["GET", "POST"])
def comments():
    """Escenario de XSS almacenado: comentarios."""
    if request.method == "POST":
        text = request.form.get("text", "")
        if text:
            storage.add_comment(text)
        return redirect(url_for("main.comments"))

    comments = storage.load_comments()
    secured_comments = [
        {
            **comment,
            "safe_text": security.secure_output(comment.get("text", ""), context="html"),
        }
        for comment in comments
    ]

    return render_template(
        "comments.html",
        comments=comments,
        secured_comments=secured_comments,
        security_mode=security.get_security_mode(),
    )

@bp.route("/contact", methods=["GET", "POST"])
def contact():
    """Punto de entrada de Blind XSS: formulario de contacto."""
    if request.method == "POST":
        message = request.form.get("message", "")
        if message:
            storage.add_message(message)
        return render_template(
            "contact.html",
            sent=True,
            security_mode=security.get_security_mode(),
        )

    return render_template(
        "contact.html",
        sent=False,
        security_mode=security.get_security_mode(),
    )

@bp.route("/admin/messages")
def admin_messages():
    """
    Panel de admin que muestra mensajes.
    Aquí se materializa Blind XSS.
    """
    messages = storage.load_messages()
    storage.log_blind_xss_event(message_count=len(messages))

    secured_messages = [
        {
            **m,
            "safe_text": security.secure_output(m.get("text", ""), context="html"),
        }
        for m in messages
    ]

    return render_template(
        "admin_messages.html",
        messages=messages,
        secured_messages=secured_messages,
        security_mode=security.get_security_mode(),
    )

@bp.route("/steal")
def steal():
    """
    Mini cookie collector: GET /steal?c=<cookie_value>.
    Registra IP y valor de c en el log.
    """
    cookie_value = request.args.get("c", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")

    if cookie_value:
        storage.log_stolen_cookie(ip=ip, cookie_value=cookie_value)

    return ("", 204)

@bp.route("/admin/cookies")
def admin_cookies():
    """Panel de admin que muestra cookies robadas."""
    entries = storage.read_stolen_cookies()
    return render_template(
        "admin_cookies.html",
        entries=entries,
        security_mode=security.get_security_mode(),
    )
