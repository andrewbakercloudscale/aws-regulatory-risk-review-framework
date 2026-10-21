"""Refresh src/exitrisk/data/direct_connect.json from AWS's public Direct Connect price list.

python scripts/refresh_direct_connect.py           # download (about 100 MB) and write
python scripts/refresh_direct_connect.py FILE      # build from a downloaded copy of index.json

Kept per region: the hourly price of a dedicated 1G, 10G and 100G port, and the per-GB price of
data transfer out over Direct Connect to a location in each country that has an AWS region.
Also the cheapest flat-rate 10G port (no per-GB charge), and the name of every Direct Connect
location, so a usage type such as AFS1-TECT1-PortUsage:10G reads as "Teraco CT1, Cape Town".
No AWS credentials are needed.
"""

from __future__ import annotations

import json
import statistics
import sys
import urllib.request
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "exitrisk" / "data"
URL = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSDirectConnect/current/index.json"
SPEEDS = ("1G", "10G", "100G")
# regions.yaml uses ISO alpha-2 country codes; the price list uses alpha-3.
ALPHA3 = {
    "AE": "ARE", "AU": "AUS", "BH": "BHR", "BR": "BRA", "CA": "CAN", "CH": "CHE", "DE": "DEU", "ES": "ESP",
    "FR": "FRA", "GB": "GBR", "HK": "HKG", "ID": "IDN", "IE": "IRL", "IL": "ISR", "IN": "IND", "IT": "ITA",
    "JP": "JPN", "KR": "KOR", "MX": "MEX", "MY": "MYS", "NZ": "NZL", "SE": "SWE", "SG": "SGP", "TH": "THA",
    "TW": "TWN", "US": "USA", "ZA": "ZAF",
}  # fmt: skip


def _price(terms: dict, sku: str) -> float | None:
    for term in terms.get(sku, {}).values():
        for dim in term["priceDimensions"].values():
            return float(dim["pricePerUnit"]["USD"])
    return None


def main(argv: list[str]) -> int:
    if argv:
        raw = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    else:
        with urllib.request.urlopen(URL, timeout=300) as resp:  # noqa: S310 - fixed https URL
            raw = json.load(resp)
    regions = yaml.safe_load((DATA / "regions.yaml").read_text(encoding="utf-8"))["regions"]
    terms = raw["terms"]["OnDemand"]
    locations: dict[str, str] = {}
    location_country: dict[str, str] = {}
    ports: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    dto: dict[str, list[tuple[str, float]]] = defaultdict(list)
    flat: dict[str, list[float]] = defaultdict(list)
    for sku, p in raw["products"].items():
        a = p["attributes"]
        usage = a.get("usagetype", "")
        parts = usage.split("-", 2)
        region = a.get("regionCode") or a.get("fromRegionCode") or ""
        if len(parts) < 3 or not region:
            continue
        code = parts[1]
        if a.get("directConnectLocation"):
            locations.setdefault(code, a["directConnectLocation"].strip())
        if a.get("alpha-3countrycode"):
            location_country.setdefault(code, a["alpha-3countrycode"])
        price = _price(terms, sku)
        if price is None:
            continue
        kind = parts[2]
        if kind.startswith("PortUsage:") and a.get("connectionType") == "Dedicated":
            speed = kind.split(":", 1)[1]
            if speed in SPEEDS:
                ports[region][speed].append(price)
        elif kind.startswith("FlatRatePortUsage:10G-Tier"):
            flat[region].append(price)
        elif kind.startswith("DataXfer-Out") and "dxfr" not in kind and "SiteLink" not in kind and price > 0:
            dto[region].append((code, price))
    alpha2 = {v: k for k, v in ALPHA3.items()}
    out_regions = {}
    for region in regions:
        if region not in ports:
            continue
        # Per-GB rate from this region to a Direct Connect location in each country (median over the
        # country's locations), so data held in Ireland but leaving through Cape Town is priced as such.
        by_country: dict[str, list[float]] = defaultdict(list)
        for c, p in dto.get(region, []):
            if location_country.get(c) in alpha2:
                by_country[alpha2[location_country[c]]].append(p)
        out_regions[region] = {
            "port_hour_usd": {s: Counter(v).most_common(1)[0][0] for s, v in sorted(ports[region].items())},
            # Flat-rate ports carry no per-GB charge; the cheapest single 10G tier, or None.
            "flat_rate_10g_hour_usd": min(flat[region]) if flat.get(region) else None,
            "dto_per_gb_usd": {c: round(statistics.median(v), 4) for c, v in sorted(by_country.items())},
        }
    out = {
        "source": URL,
        "publication_date": raw.get("publicationDate", ""),
        "fetched": date.today().isoformat(),
        "regions": dict(sorted(out_regions.items())),
        "locations": dict(sorted(locations.items())),
    }
    path = DATA / "direct_connect.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}: {len(out_regions)} regions, {len(locations)} locations, "
          f"published {out['publication_date']}")  # fmt: skip
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
