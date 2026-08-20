# Demo Run

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
python3 evaluate.py
```

The command should complete without network access or private credentials.


## Optional API

Start the read-only local service with:

```bash
uvicorn api:app --app-dir src --host 127.0.0.1 --port 8000
```

The service exposes `/health` and `/analyze`. It does not execute endpoint
commands or contact external systems.
