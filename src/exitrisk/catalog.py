"""The service risk catalog: which AWS services are how hard to leave, and why."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path

import yaml

TIER_RANGE = range(1, 6)
REQUIRED_FIELDS = ("service", "display", "category", "tier", "why", "migration", "effort_weeks", "duration")


@dataclass(frozen=True)
class ServiceInfo:
    service: str
    display: str
    category: str
    tier: int
    why: str
    migration: str
    effort_weeks: float
    duration: str
    targets: dict = field(default_factory=dict)
    aliases: tuple[str, ...] = ()
    excluded: bool = False
    classified: bool = True

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "display": self.display,
            "category": self.category,
            "tier": self.tier,
            "why": self.why,
            "migration": self.migration,
            "effort_weeks": self.effort_weeks,
            "duration": self.duration,
            "targets": dict(self.targets),
            "aliases": list(self.aliases),
            "excluded": self.excluded,
            "classified": self.classified,
        }


class CatalogError(ValueError):
    pass


class Catalog:
    def __init__(self, raw: dict):
        self.version: str = str(raw.get("version", "unversioned"))
        self.tiers: dict[int, dict] = {int(k): v for k, v in raw["tiers"].items()}
        self._unclassified = raw["unclassified"]
        self.services: list[ServiceInfo] = []
        self._index: dict[str, ServiceInfo] = {}
        self._index_ci: dict[str, ServiceInfo] = {}
        for entry in raw["services"]:
            missing = [f for f in REQUIRED_FIELDS if f not in entry]
            if missing:
                raise CatalogError(f"catalog entry {entry.get('service', '?')!r} missing {missing}")
            if int(entry["tier"]) not in TIER_RANGE:
                raise CatalogError(f"catalog entry {entry['service']!r} has tier {entry['tier']} outside 1-5")
            info = ServiceInfo(
                service=entry["service"],
                display=entry["display"],
                category=entry["category"],
                tier=int(entry["tier"]),
                why=" ".join(str(entry["why"]).split()),
                migration=" ".join(str(entry["migration"]).split()),
                effort_weeks=float(entry["effort_weeks"]),
                duration=str(entry["duration"]),
                targets=entry.get("targets") or {},
                aliases=tuple(entry.get("aliases") or ()),
                excluded=bool(entry.get("excluded", False)),
            )
            for name in (info.service, *info.aliases):
                if name in self._index:
                    raise CatalogError(f"service name {name!r} appears twice in the catalog")
                self._index[name] = info
                self._index_ci[name.casefold()] = info
            self.services.append(info)

    def tier_score(self, tier: int) -> float:
        return float(self.tiers[tier]["score"])

    def tier_label(self, tier: int) -> str:
        return str(self.tiers[tier]["label"])

    def lookup(self, service_name: str) -> ServiceInfo:
        """Find a service by its Cost Explorer name. Unknown services get the unclassified default."""
        hit = self._index.get(service_name) or self._index_ci.get(service_name.casefold())
        if hit:
            return hit
        u = self._unclassified
        return ServiceInfo(
            service=service_name,
            display=_short_name(service_name),
            category="Unclassified",
            tier=int(u["tier"]),
            why=u["why"],
            migration=u["migration"],
            effort_weeks=float(u["effort_weeks"]),
            duration=u["duration"],
            classified=False,
        )

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "tiers": {k: v for k, v in self.tiers.items()},
            "services": [s.to_dict() for s in self.services if not s.excluded],
        }


def _short_name(name: str) -> str:
    for prefix in ("Amazon ", "AWS "):
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


@lru_cache(maxsize=4)
def load_catalog(path: str | None = None) -> Catalog:
    if path:
        text = Path(path).read_text(encoding="utf-8")
    else:
        text = resources.files("exitrisk").joinpath("data/service_catalog.yaml").read_text(encoding="utf-8")
    return Catalog(yaml.safe_load(text))
