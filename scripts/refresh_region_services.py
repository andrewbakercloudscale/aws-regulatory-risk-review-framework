"""Refresh src/exitrisk/data/region_services.json from AWS's public regional services table.

python scripts/refresh_region_services.py           # download and write
python scripts/refresh_region_services.py FILE      # build from a downloaded copy of index.json

The table is the one behind https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/.
It needs no AWS credentials. Only the services named in data/regions.yaml are kept, so the
file stays small and a renamed service shows up as a failure here rather than as "not verified"
in every report.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "exitrisk" / "data"
URL = "https://api.regional-table.region-services.aws.a2z.com/index.json"


def main(argv: list[str]) -> int:
    if argv:
        raw = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    else:
        with urllib.request.urlopen(URL, timeout=60) as resp:  # noqa: S310 - fixed https URL
            raw = json.load(resp)
    cfg = yaml.safe_load((DATA / "regions.yaml").read_text(encoding="utf-8"))
    wanted = {v["regional"] for v in cfg["services"].values() if v["regional"] not in (None, "global")}
    services: dict[str, set[str]] = {}
    for row in raw["prices"]:
        a = row["attributes"]
        if a["aws:serviceName"] in wanted:
            services.setdefault(a["aws:serviceName"], set()).add(a["aws:region"])
    missing = sorted(wanted - set(services))
    if missing:
        print(f"not in the AWS table (rename in regions.yaml or set regional: null): {missing}", file=sys.stderr)
        return 1
    out = {
        "source": URL,
        "source_version": raw.get("metadata", {}).get("source:version", ""),
        "fetched": date.today().isoformat(),
        "services": {k: sorted(v) for k, v in sorted(services.items())},
    }
    path = DATA / "region_services.json"
    path.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}: {len(services)} services, source version {out['source_version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
