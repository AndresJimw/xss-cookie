import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask


def create_app() -> Flask:
    """Crea y configura la aplicación Flask."""
    # Cargar variables desde .env
    base_dir = Path(__file__).resolve().parents[1]
    env_path = base_dir / ".env"
    if env_path.exists():
        load_dotenv(env_path)

    app = Flask(__name__)

    # Configuración básica
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")

    # Modo de seguridad del mitigador simple
    app.config["SECURITY_MODE"] = os.getenv("SECURITY_MODE", "off")

    # Registrar rutas y hooks
    from . import routes
    routes.init_app(app)

    return app
