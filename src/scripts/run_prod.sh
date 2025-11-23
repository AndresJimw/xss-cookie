#!/usr/bin/env bash
# Run Flask app in "production" mode for the demo on EC2

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/.."

cd "${PROJECT_ROOT}"

source .venv/bin/activate

export FLASK_ENV=production
# Opcional: activar mitigación fuerte en el demo final
# export SECURITY_MODE=block

python -m app.main
