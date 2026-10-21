"""AWS Organizations: the OU tree and the accounts under an OU (recursively)."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import boto3

from ..aws_session import BOTO_CONFIG
from ..logging_config import get_logger
from ..parallel import pmap

log = get_logger("organizations")


@dataclass
class Account:
    id: str
    name: str
    email: str
    status: str
    ou_id: str
    ou_path: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _client(session: boto3.Session):
    return session.client("organizations", region_name="us-east-1", config=BOTO_CONFIG)


def describe_org(session: boto3.Session) -> dict:
    org = _client(session).describe_organization()["Organization"]
    return {"id": org["Id"], "management_account_id": org["MasterAccountId"]}


def list_ou_tree(session: boto3.Session) -> dict:
    """Return the full OU tree as nested dicts: {id, name, path, accounts, children: [...]}.

    ``accounts`` counts the accounts directly in that node, so the picker can show how big each OU is.
    """
    client = _client(session)
    root = client.list_roots()["Roots"][0]
    tree = {"id": root["Id"], "name": "Root", "path": "Root", "children": []}
    paginator = client.get_paginator("list_organizational_units_for_parent")
    accounts = client.get_paginator("list_accounts_for_parent")

    def expand(node: dict) -> list[dict]:
        node["accounts"] = sum(len(p["Accounts"]) for p in accounts.paginate(ParentId=node["id"]))
        for page in paginator.paginate(ParentId=node["id"]):
            for ou in page["OrganizationalUnits"]:
                child = {"id": ou["Id"], "name": ou["Name"], "path": f"{node['path']} / {ou['Name']}", "children": []}
                node["children"].append(child)
        node["children"].sort(key=lambda c: c["name"].lower())
        return node["children"]

    # One level at a time, siblings in parallel: a 10-OU tree takes ~3 round trips instead of ~11.
    # Few workers, because Organizations throttles hard (botocore retries what does get throttled).
    level = [tree]
    while level:
        level = [child for children in pmap(expand, level) for child in children]
    return tree


# The OU tree takes ~10 s to read in a large organisation, so the console's OU picker caches it.
# Scans never use this cache: they always read the tree fresh. Keyed by AWS profile.
TREE_CACHE_SECONDS = 900
_tree_cache: dict[str, tuple[float, dict, dict]] = {}
_tree_lock = threading.Lock()


def cached_org_and_tree(profile: str | None) -> tuple[dict, dict] | None:
    """(describe_org, list_ou_tree) for this profile if read in the last 15 minutes."""
    with _tree_lock:
        hit = _tree_cache.get(profile or "")
    if hit and time.monotonic() - hit[0] < TREE_CACHE_SECONDS:
        log.info("OU tree from cache (read %d s ago)", time.monotonic() - hit[0])
        return hit[1], hit[2]
    return None


def remember_org_and_tree(profile: str | None, org: dict, tree: dict) -> None:
    with _tree_lock:
        _tree_cache[profile or ""] = (time.monotonic(), org, tree)


def clear_tree_cache() -> None:
    with _tree_lock:
        _tree_cache.clear()


def find_ou(tree: dict, ou_id: str) -> dict | None:
    if tree["id"] == ou_id:
        return tree
    for child in tree["children"]:
        hit = find_ou(child, ou_id)
        if hit:
            return hit
    return None


def list_accounts_under(session: boto3.Session, ou: dict) -> list[Account]:
    """Every account in ``ou`` and all of its descendant OUs."""
    paginator = _client(session).get_paginator("list_accounts_for_parent")
    nodes, stack = [], [ou]
    while stack:
        node = stack.pop()
        nodes.append(node)
        stack.extend(node["children"])

    def direct(node: dict) -> list[Account]:
        return [
            Account(
                id=a["Id"],
                name=a.get("Name", a["Id"]),
                email=a.get("Email", ""),
                status=a.get("Status", a.get("State", "UNKNOWN")),
                ou_id=node["id"],
                ou_path=node["path"],
            )
            for page in paginator.paginate(ParentId=node["id"])
            for a in page["Accounts"]
        ]

    accounts = [a for found in pmap(direct, nodes) for a in found]
    log.info("found %d accounts under %s", len(accounts), ou["path"])
    return accounts


def fetch_account_tags(session: boto3.Session, account_ids: list[str]) -> dict[str, dict[str, str]]:
    """Tags on each account (criticality, channel, product...). Keys are trimmed: tags typed by hand
    often carry a trailing space. Raises on the first refusal, so the caller can report it once."""
    client = _client(session)

    def one(account_id: str) -> tuple[str, dict[str, str]]:
        tags: dict[str, str] = {}
        for page in client.get_paginator("list_tags_for_resource").paginate(ResourceId=account_id):
            for t in page["Tags"]:
                tags.setdefault(t["Key"].strip(), t["Value"].strip())
        return account_id, tags

    out = dict(pmap(one, account_ids))
    log.info("read tags for %d accounts (%d tagged)", len(out), sum(1 for t in out.values() if t))
    return out
