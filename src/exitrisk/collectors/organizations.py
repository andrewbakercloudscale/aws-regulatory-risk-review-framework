"""AWS Organizations: the OU tree and the accounts under an OU (recursively)."""

from __future__ import annotations

from dataclasses import dataclass

import boto3

from ..aws_session import BOTO_CONFIG
from ..logging_config import get_logger

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
    """Return the full OU tree as nested dicts: {id, name, path, children: [...]}."""
    client = _client(session)
    root = client.list_roots()["Roots"][0]
    tree = {"id": root["Id"], "name": "Root", "path": "Root", "children": []}
    stack = [tree]
    paginator = client.get_paginator("list_organizational_units_for_parent")
    while stack:
        node = stack.pop()
        for page in paginator.paginate(ParentId=node["id"]):
            for ou in page["OrganizationalUnits"]:
                child = {"id": ou["Id"], "name": ou["Name"], "path": f"{node['path']} / {ou['Name']}", "children": []}
                node["children"].append(child)
                stack.append(child)
        node["children"].sort(key=lambda c: c["name"].lower())
    return tree


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
    client = _client(session)
    paginator = client.get_paginator("list_accounts_for_parent")
    accounts: list[Account] = []
    stack = [ou]
    while stack:
        node = stack.pop()
        for page in paginator.paginate(ParentId=node["id"]):
            for a in page["Accounts"]:
                accounts.append(
                    Account(
                        id=a["Id"],
                        name=a.get("Name", a["Id"]),
                        email=a.get("Email", ""),
                        status=a.get("Status", a.get("State", "UNKNOWN")),
                        ou_id=node["id"],
                        ou_path=node["path"],
                    )
                )
        stack.extend(node["children"])
    log.info("found %d accounts under %s", len(accounts), ou["path"])
    return accounts
