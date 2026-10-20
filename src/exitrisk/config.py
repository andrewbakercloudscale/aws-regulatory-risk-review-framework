"""Runtime settings, read from the environment so the tool needs no config file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_data_dir() -> Path:
    return Path(os.environ.get("EXITRISK_DATA_DIR", Path.home() / ".exitrisk")).expanduser()


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=_default_data_dir)
    log_level: str = field(default_factory=lambda: os.environ.get("EXITRISK_LOG_LEVEL", "INFO").upper())
    # Cost Explorer and Organizations are global services served from us-east-1.
    billing_region: str = "us-east-1"
    max_workers: int = field(default_factory=lambda: int(os.environ.get("EXITRISK_MAX_WORKERS", "8")))

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def log_file(self) -> Path:
        return self.logs_dir / "exitrisk.log"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.scans_dir, self.logs_dir):
            d.mkdir(parents=True, exist_ok=True)
            # Scan results name every account and its spend: keep them private to the user.
            os.chmod(d, 0o700)


settings = Settings()
