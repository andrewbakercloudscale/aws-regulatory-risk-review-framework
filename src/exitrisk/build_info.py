"""Which build of the console is running, and when it was made, for the version shown in the top bar.

A release is the tag ``v<version>``; its commit time is the release time. Run from a checkout (an editable
install), commits made since the tag are counted, so a console running work not yet released says so.
Installed from a wheel there is no git: the package's own file time stands in.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from . import __version__

HERE = Path(__file__).resolve().parent


def _git(*args: str) -> str:
    out = subprocess.run(["git", "-C", str(HERE), *args], capture_output=True, text=True, timeout=5, check=False)
    return out.stdout.strip() if out.returncode == 0 else ""


@lru_cache(maxsize=1)
def build_info() -> dict:
    """{version, released_at (ISO, or None), commits_since (int), built_at (ISO of the code running)}."""
    tag = f"v{__version__}"
    released = commits = head = None
    try:
        released = _git("log", "-1", "--format=%cI", tag) or None
        head = _git("log", "-1", "--format=%cI", "HEAD") or None
        count = _git("rev-list", "--count", f"{tag}..HEAD")
        commits = int(count) if count.isdigit() else None
    except (OSError, subprocess.SubprocessError):
        pass
    if not head:
        head = datetime.fromtimestamp((HERE / "__init__.py").stat().st_mtime, timezone.utc).isoformat(
            timespec="seconds"
        )
    return {"version": __version__, "released_at": released, "commits_since": commits or 0, "built_at": head}
