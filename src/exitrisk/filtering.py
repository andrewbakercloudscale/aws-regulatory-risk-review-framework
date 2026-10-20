"""Account-name filtering, e.g. keep only production accounts ("prod", "prd-")."""

from __future__ import annotations

import re
from dataclasses import dataclass

MODES = ("contains", "prefix", "suffix", "regex")
_MAX_PATTERN = 200


class FilterError(ValueError):
    pass


def _split(text: str | None) -> list[str]:
    return [p.strip() for p in (text or "").split(",") if p.strip()]


@dataclass
class AccountFilter:
    include: str = ""
    exclude: str = ""
    mode: str = "contains"
    case_sensitive: bool = False

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise FilterError(f"mode must be one of {', '.join(MODES)}")
        for text in (self.include, self.exclude):
            if len(text or "") > _MAX_PATTERN:
                raise FilterError(f"filter patterns are limited to {_MAX_PATTERN} characters")
        flags = 0 if self.case_sensitive else re.IGNORECASE
        self._inc = [self._compile(p, flags) for p in _split(self.include)]
        self._exc = [self._compile(p, flags) for p in _split(self.exclude)]

    def _compile(self, pattern: str, flags: int) -> re.Pattern:
        if self.mode == "regex":
            try:
                return re.compile(pattern, flags)
            except re.error as exc:
                raise FilterError(f"invalid regular expression {pattern!r}: {exc}") from exc
        body = re.escape(pattern)
        return re.compile({"contains": body, "prefix": "^" + body, "suffix": body + "$"}[self.mode], flags)

    @property
    def active(self) -> bool:
        return bool(self._inc or self._exc)

    def matches(self, name: str) -> bool:
        if self._inc and not any(p.search(name) for p in self._inc):
            return False
        return not any(p.search(name) for p in self._exc)

    def describe(self) -> str:
        if not self.active:
            return "All accounts"
        parts = []
        if self._inc:
            parts.append(f"name {self.mode} {' or '.join(repr(p) for p in _split(self.include))}")
        if self._exc:
            parts.append(f"excluding {' or '.join(repr(p) for p in _split(self.exclude))}")
        return "; ".join(parts) + ("" if not self.case_sensitive else " (case-sensitive)")

    def to_dict(self) -> dict:
        return {
            "include": self.include,
            "exclude": self.exclude,
            "mode": self.mode,
            "case_sensitive": self.case_sensitive,
            "description": self.describe(),
        }
