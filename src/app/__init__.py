import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask


def create_app() -> Flask:
    base_dir = Path(__file__).resolve().parents[1]
    env_file = base_dir / ".env"
    if env_file.exists():
        load_dotenv(env_file)

    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    app.config["SECURITY_MODE"] = os.getenv("SECURITY_MODE", "off").lower()

    from . import routes
    routes.init_app(app)

    return app
