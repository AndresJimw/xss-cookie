from . import create_app

def main() -> None:
    """Punto de entrada para ejecutar la app."""
    app = create_app()
    # 0.0.0.0 permite acceso externo
    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    main()
