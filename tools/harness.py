#!/usr/bin/env python3
"""Run Agent Zero's real /api dispatcher on a bare Flask app, for reproduction.

    AZ_ROOT=/path/to/agent-zero python3 tools/harness.py [port]

Why a harness and not `run_ui.py`: a full boot pulls in the LLM stack, the vector
store and the secrets extension. None of the four links under test touches them.
This mounts the project's own `helpers.api.register_api_route()`, and that
dispatcher loads `api/<name>.py` from disk by filename, so every handler exercised
by the PoC is original code. Nothing about the auth, CSRF, settings, file-read or
rfc paths is reimplemented here.

Two things this deliberately does:

  * stubs the `helpers` package name, because the checkout ships no
    `helpers/__init__.py` and an unrelated `helpers` package in dist-packages
    would otherwise win the import;
  * loads `usr/.env` the way `run_ui.py` does, because the rfc path reads
    `RFC_PASSWORD` through os.getenv.

Create `usr/.env` with an `RFC_PASSWORD=` line first if you want to reach link 4.
"""
from __future__ import annotations

import os
import pathlib
import sys
import threading
import types

root = os.environ.get("AZ_ROOT")
if not root:
    sys.exit("set AZ_ROOT to the agent-zero checkout")

ROOT = pathlib.Path(root).resolve()
if not (ROOT / "helpers" / "api.py").is_file():
    sys.exit(f"no helpers/api.py under {ROOT}")
sys.path.insert(0, str(ROOT))

_stub = types.ModuleType("helpers")
_stub.__path__ = [str(ROOT / "helpers")]
sys.modules["helpers"] = _stub

from flask import Flask  # noqa: E402

from helpers import dotenv  # noqa: E402
from helpers.api import register_api_route  # noqa: E402

dotenv.load_dotenv()

port = int(sys.argv[1]) if len(sys.argv) > 1 else 50001

app = Flask(__name__)
app.secret_key = "harness-secret-not-a-target-value"
register_api_route(app, threading.RLock())

if __name__ == "__main__":
    print(f"harness on http://127.0.0.1:{port}  (root={ROOT})")
    app.run(host="127.0.0.1", port=port, threaded=True, use_reloader=False)
