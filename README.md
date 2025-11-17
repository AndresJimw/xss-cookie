# XSS Cookie Lab

Educational demo application to study Cross-Site Scripting (XSS) and
cookie stealing scenarios in a controlled environment.

## Features

- **Reflected XSS** scenario at `/search`
- **Stored XSS** scenario at `/comments`
- **Blind XSS** scenario at `/contact` and `/admin/messages`
- Simple **cookie collector** endpoint at `/steal`,
  with a basic log viewer at `/admin/cookies`
- Lightweight mitigation module (`security.py`) with modes:
  - `vulnerable`
  - `log`
  - `block`

## Requirements

- Python 3.10+ recommended
- `Flask` (see `requirements.txt`)

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .\.venv\Scripts\Activate     # Windows PowerShell

pip install -r requirements.txt

python -m app.main
