from __future__ import annotations

from flask import (
    Blueprint,
    Flask,
    redirect,
    render_template,
    request,
    url_for,
    jsonify,
)

from . import storage
from . import security

bp = Blueprint("main", __name__)

def init_app(app: Flask) -> None:
    app.register_blueprint(bp)

    @app.after_request
    def _apply_security_headers(response):
        return security.apply_security_headers(response)

@bp.route("/")
def index():
    security_mode = security.get_security_mode()
    return render_template("index.html", security_mode=security_mode)

@bp.route("/search")
def search():
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
    if request.method == "POST":
        text = request.form.get("text", "")
        if text:
            storage.add_comment(text)
        return redirect(url_for("main.comments"))

    comments = storage.load_comments()

    secured_comments = [
        {
            **comment,
            "safe_text": security.secure_output(
                comment.get("text", ""),
                context="html",
            ),
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
    messages = storage.load_messages()
    storage.log_blind_xss_event(message_count=len(messages))

    secured_messages = [
        {
            **m,
            "safe_text": security.secure_output(
                m.get("text", ""),
                context="html",
            ),
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
    cookie_value = request.args.get("c", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")

    if cookie_value:
        storage.log_stolen_cookie(ip=ip, cookie_value=cookie_value)

    return ("", 204)

@bp.route("/admin/cookies")
def admin_cookies():
    entries = storage.read_stolen_cookies()
    return render_template(
        "admin_cookies.html",
        entries=entries,
        security_mode=security.get_security_mode(),
    )


@bp.route("/api/test_payload", methods=["POST"])
def api_test_payload():
    """
    API endpoint used by the experiments notebook.
    """
    data = request.get_json(silent=True) or {}
    payload = data.get("payload") or ""
    context = (data.get("context") or "html").lower()

    analysis = security.analyze_input(payload, context=context)
    sanitized = security.secure_output(payload, context=context)
    mode = security.get_security_mode()

    is_suspicious = bool(analysis.get("is_suspicious"))
    reasons = analysis.get("reasons", [])
    categories = analysis.get("categories", [])
    main_category = analysis.get("main_category")
    if not main_category:
        main_category = "benign" if not is_suspicious else "unknown"

    blocked = False
    if mode == "block" and is_suspicious:
        blocked = True

    response_data = {
        "original": payload,
        "sanitized": sanitized,
        "blocked": blocked,
        "category": main_category,
        "mode": mode,
        "is_suspicious": is_suspicious,
        "reasons": reasons,
        "categories": categories,
        "context": context,
    }

    return jsonify(response_data)
