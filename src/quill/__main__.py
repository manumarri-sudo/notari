"""Allow `python -m quill ...` (and the daemon spawn path).

The daemon helper in watch.py spawns
    [sys.executable, "-m", "quill", "watch", "--daemon-child", ...]
so the same Python interpreter that installed the package runs the
detached dashboard process. This module just delegates to the typer
app defined in cli.py.
"""

from quill.cli import app

if __name__ == "__main__":
    app()
