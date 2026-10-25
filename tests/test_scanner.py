"""Scanner failure handling: errors become issues and the scan document is still saved."""

import pytest
from botocore.exceptions import ClientError

from exitrisk import scanner, store
from exitrisk.scanner import ScanJob, ScanParams


def test_params_validation():
    with pytest.raises(ValueError):
        ScanParams(months=0).validate()
    with pytest.raises(ValueError):
        ScanParams(inventory=True).validate()


def test_auth_failure_is_recorded_and_saved(monkeypatch):
    def boom(_session):
        raise ClientError({"Error": {"Code": "ExpiredToken", "Message": "token expired"}}, "GetCallerIdentity")

    monkeypatch.setattr(scanner, "caller_identity", boom)
    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    job = ScanJob(id=store.new_scan_id(), params=ScanParams(profile="p"))
    scanner._run_safely(job)
    assert job.status == "failed"
    saved = store.load_scan(job.id)
    assert saved["status"] == "failed"
    assert any(i["severity"] == "critical" and i["error_code"] == "ExpiredToken" for i in saved["issues"])
    assert any("Touch ID" in i["hint"] for i in saved["issues"])


def test_organizations_unavailable_falls_back_to_single_account(monkeypatch):
    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    monkeypatch.setattr(scanner, "caller_identity", lambda s: {"account_id": "123456789012", "arn": "arn:x"})

    def no_org(_s):
        raise ClientError({"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "no org"}}, "Describe")

    monkeypatch.setattr(scanner.organizations, "describe_org", no_org)
    monkeypatch.setattr(scanner.cost, "fetch_storage", lambda s, ids, services: [])
    monkeypatch.setattr(scanner.cost, "fetch_commitments", lambda s: [])
    monkeypatch.setattr(
        scanner.cost,
        "fetch_costs",
        lambda s, ids, m, *_: (
            [{"month": "2026-09", "account_id": ids[0], "service": "AWS Lambda", "amount": 10.0}],
            {"start": "2026-09-01", "end": "2026-10-01", "months": 1},
        ),
    )
    job = ScanJob(id=store.new_scan_id(), params=ScanParams())
    doc = scanner.run_scan(job)
    assert doc["status"] == "complete"
    assert doc["accounts"][0]["id"] == "123456789012"
    assert any(i["category"] == "organizations" for i in doc["issues"])


def test_member_account_fallback_names_management_account(monkeypatch):
    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    monkeypatch.setattr(scanner, "caller_identity", lambda s: {"account_id": "222222222222", "arn": "arn:x"})
    monkeypatch.setattr(
        scanner.organizations, "describe_org", lambda s: {"id": "o-1", "management_account_id": "111111111111"}
    )

    def denied(_s, *_):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "ListRoots")

    monkeypatch.setattr(scanner.organizations, "list_ou_tree", denied)
    monkeypatch.setattr(
        scanner.cost,
        "fetch_costs",
        lambda s, ids, m, *_: ([], {"start": "2026-09-01", "end": "2026-10-01", "months": 1}),
    )
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    org_issue = next(i for i in doc["issues"] if i["category"] == "organizations")
    assert "111111111111" in org_issue["message"] and "111111111111" in org_issue["hint"]
    assert doc["ou"]["name"] == "Single member account"


def test_several_ous_scan_each_account_once(monkeypatch):
    def node(i, name, path, children=()):
        return {"id": i, "name": name, "path": path, "children": list(children)}

    child = node("ou-a-kid", "kid", "Root / A / kid")
    tree = node("r-1", "Root", "Root", [node("ou-a", "A", "Root / A", [child]), node("ou-b", "B", "Root / B")])
    members = {"ou-a": ["1", "2"], "ou-a-kid": ["2"], "ou-b": ["3"]}  # account 2 sits under A and its child

    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    monkeypatch.setattr(scanner, "caller_identity", lambda s: {"account_id": "111111111111", "arn": "arn:x"})
    monkeypatch.setattr(
        scanner.organizations, "describe_org", lambda s: {"id": "o-1", "management_account_id": "111111111111"}
    )
    monkeypatch.setattr(scanner.organizations, "list_ou_tree", lambda s, *_: tree)
    monkeypatch.setattr(
        scanner.organizations,
        "list_accounts_under",
        lambda s, ou, *_: [
            scanner.organizations.Account(i, f"acct-{i}", "", "ACTIVE", ou["id"], ou["path"]) for i in members[ou["id"]]
        ],
    )
    monkeypatch.setattr(
        scanner.cost,
        "fetch_costs",
        lambda s, ids, m, *_: ([], {"start": "2026-09-01", "end": "2026-10-01", "months": 1}),
    )
    params = ScanParams(ou_ids=["ou-a", "ou-a-kid", "ou-b"])
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=params))
    assert sorted(a["id"] for a in doc["accounts"]) == ["1", "2", "3"]
    assert doc["ou"]["name"] == "A + kid + B"
    assert [o["id"] for o in doc["ous"]] == ["ou-a", "ou-a-kid", "ou-b"]

    with pytest.raises(scanner.ScanFailed, match="ou-zzz"):
        scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams(ou_ids=["ou-zzz"])))


def test_scan_reads_the_ou_tree_fresh_not_from_the_picker_cache(monkeypatch):
    stale = {"id": "r-1", "name": "Root", "path": "Root", "children": []}
    fresh = {
        "id": "r-1",
        "name": "Root",
        "path": "Root",
        "children": [{"id": "ou-new", "name": "New", "path": "Root / New", "children": []}],
    }
    scanner.organizations.remember_org_and_tree(None, {"id": "o-1"}, stale)  # the OU picker read it earlier
    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    monkeypatch.setattr(scanner, "caller_identity", lambda s: {"account_id": "111111111111", "arn": "arn:x"})
    monkeypatch.setattr(
        scanner.organizations, "describe_org", lambda s: {"id": "o-1", "management_account_id": "111111111111"}
    )
    monkeypatch.setattr(scanner.organizations, "list_ou_tree", lambda s, *_: fresh)
    monkeypatch.setattr(
        scanner.organizations,
        "list_accounts_under",
        lambda s, ou, *_: [scanner.organizations.Account("1", "acct-1", "", "ACTIVE", ou["id"], ou["path"])],
    )
    monkeypatch.setattr(
        scanner.cost,
        "fetch_costs",
        lambda s, ids, m, *_: ([], {"start": "2026-09-01", "end": "2026-10-01", "months": 1}),
    )
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams(ou_ids=["ou-new"])))
    assert doc["ou"]["id"] == "ou-new"  # an OU created after the picker's read is found
    assert scanner.organizations.cached_org_and_tree(None)[1] is fresh  # and the picker sees it too


def _single_account(monkeypatch):
    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    monkeypatch.setattr(scanner.cost, "fetch_commitments", lambda s: [])
    monkeypatch.setattr(scanner, "caller_identity", lambda s: {"account_id": "123456789012", "arn": "arn:x"})

    def no_org(_s):
        raise ClientError({"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "no org"}}, "Describe")

    monkeypatch.setattr(scanner.organizations, "describe_org", no_org)
    monkeypatch.setattr(
        scanner.cost,
        "fetch_costs",
        lambda s, ids, m, *_: (
            [{"month": "2026-09", "account_id": ids[0], "service": "AWS Lambda", "amount": 10.0}],
            {"start": "2026-09-01", "end": "2026-10-01", "months": 1},
        ),
    )


def test_spend_by_region_is_saved(monkeypatch):
    _single_account(monkeypatch)
    rows = [{"account_id": "123456789012", "service": "AWS Lambda", "region": "eu-west-1", "monthly": 10.0}]
    monkeypatch.setattr(scanner.cost, "fetch_region_costs", lambda s, ids, m, *_: rows)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    assert doc["region_costs"] == rows
    assert store.load_scan(doc["id"])["region_costs"] == rows


@pytest.mark.parametrize(
    "error",
    [
        ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "GetCostAndUsage"),
        KeyError("Groups"),  # a bug, not an AWS refusal: still never fails the scan
    ],
)
def test_spend_by_region_failure_is_an_issue_not_a_failed_scan(monkeypatch, caplog, error):
    _single_account(monkeypatch)

    def boom(*_a):
        raise error

    monkeypatch.setattr(scanner.cost, "fetch_region_costs", boom)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    assert doc["status"] == "complete" and not doc["region_costs"]
    issue = next(i for i in doc["issues"] if "spend by region" in i["message"])
    assert issue["severity"] == "warning" and "one region" in issue["hint"]
    if isinstance(error, KeyError):
        assert any(r.exc_info for r in caplog.records if "unexpected" in r.getMessage())


def test_storage_failure_is_an_issue_not_a_failed_scan(monkeypatch):
    _single_account(monkeypatch)
    monkeypatch.setattr(scanner.cost, "fetch_region_costs", lambda s, ids, m, *_: [])

    def boom(*_a):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "GetCostAndUsage")

    monkeypatch.setattr(scanner.cost, "fetch_storage", boom)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    assert doc["status"] == "complete" and doc["storage"] is None
    assert any("data stored unavailable" in i["message"] for i in doc["issues"])


def _org(monkeypatch):
    """A one-OU organisation with two accounts, spend and nothing else."""
    from exitrisk.collectors.organizations import Account

    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    monkeypatch.setattr(scanner, "caller_identity", lambda s: {"account_id": "111111111111", "arn": "arn:x"})
    monkeypatch.setattr(
        scanner.organizations, "describe_org", lambda s: {"id": "o-1", "management_account_id": "111111111111"}
    )
    monkeypatch.setattr(
        scanner.organizations,
        "list_ou_tree",
        lambda s, *_: {"id": "r-1", "name": "Root", "path": "Root", "children": []},
    )
    monkeypatch.setattr(
        scanner.organizations,
        "list_accounts_under",
        lambda s, ou, *_: [
            Account(i, f"acct-{i[-1]}", "", "ACTIVE", "r-1", "Root") for i in ("222222222222", "333333333333")
        ],
    )
    monkeypatch.setattr(
        scanner.cost,
        "fetch_costs",
        lambda s, ids, m, *_: (
            [{"month": "2026-09", "account_id": i, "service": "AWS Lambda", "amount": 10.0} for i in ids],
            {"start": "2026-09-01", "end": "2026-10-01", "months": 1},
        ),
    )
    monkeypatch.setattr(scanner.cost, "fetch_region_costs", lambda s, ids, m, *_: [])
    monkeypatch.setattr(scanner.cost, "fetch_storage", lambda s, ids, services: [])
    monkeypatch.setattr(scanner.cost, "fetch_commitments", lambda s: [])


def test_account_tags_are_saved_on_accounts(monkeypatch):
    _org(monkeypatch)
    monkeypatch.setattr(
        scanner.organizations, "fetch_account_tags", lambda s, ids: {"222222222222": {"Criticality": "Tier 1"}}
    )
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    tags = {a["id"]: a["tags"] for a in doc["accounts"]}
    assert tags == {"222222222222": {"Criticality": "Tier 1"}, "333333333333": {}}


def test_account_tags_refused_is_a_warning(monkeypatch):
    _org(monkeypatch)

    def denied(*_a):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "ListTagsForResource")

    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", denied)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    assert doc["status"] == "complete" and all("tags" not in a for a in doc["accounts"])
    issue = next(i for i in doc["issues"] if "account tags" in i["message"])
    assert issue["severity"] == "warning" and "ListTagsForResource" in issue["hint"]


def test_commitments_failure_is_an_issue_not_a_failed_scan(monkeypatch):
    _single_account(monkeypatch)
    monkeypatch.setattr(scanner.cost, "fetch_region_costs", lambda s, ids, m, *_: [])

    def boom(*_a):
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "GetReservationUtilization"
        )

    monkeypatch.setattr(scanner.cost, "fetch_commitments", boom)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    assert doc["status"] == "complete" and doc["commitments"] is None
    assert any("Savings Plans and reservations unavailable" in i["message"] for i in doc["issues"])


def test_expired_sign_in_mid_scan_makes_it_partial(monkeypatch):
    _org(monkeypatch)
    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", lambda s, ids: {})

    def expired(*_a):
        raise ClientError({"Error": {"Code": "ExpiredToken", "Message": "expired"}}, "GetReservationUtilization")

    monkeypatch.setattr(scanner.cost, "fetch_commitments", expired)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    assert doc["status"] == "partial"
    assert "commitments" in doc["unavailable"] and doc["commitments"] is None


def test_one_account_inventory_bug_does_not_fail_the_scan(monkeypatch, caplog):
    _org(monkeypatch)
    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", lambda s, ids: {})
    monkeypatch.setattr(scanner, "member_session", lambda s, pr, a, r, j: object())

    def inv(_s, account_id, _regions, dependencies=False):
        if account_id == "222222222222":
            raise KeyError("Reservations")
        return {"resources": {}}, []

    monkeypatch.setattr(scanner.inventory, "inventory_account", inv)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams(inventory=True, role_name="r")))
    assert doc["status"] == "partial" and list(doc["inventory"]) == ["333333333333"]
    assert any(i["account_id"] == "222222222222" and i["severity"] == "error" for i in doc["issues"])
    assert any(r.exc_info for r in caplog.records if "unexpected" in r.getMessage())


def test_bad_worker_setting_falls_back():
    from exitrisk.config import _workers

    assert _workers("") == 8 and _workers("abc") == 8 and _workers("0") == 1 and _workers("12") == 12


def test_inventory_without_role_uses_identity_center_permission_set(monkeypatch):
    monkeypatch.setattr(scanner.sso, "profile_permission_set", lambda p: ("corp", "CTO-Read") if p == "sso" else None)
    ScanParams(inventory=True, profile="sso").validate()
    with pytest.raises(ValueError, match="IAM Identity Center"):
        ScanParams(inventory=True, profile="keys").validate()


def test_deep_scan_waits_for_a_new_sign_in_then_carries_on(monkeypatch):
    _org(monkeypatch)
    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", lambda s, ids: {})
    monkeypatch.setattr(scanner.sso, "profile_permission_set", lambda p: ("corp", "CTO-Read"))
    monkeypatch.setattr(scanner, "SIGN_IN_POLL_SECONDS", 0.01)
    signed_in = {"now": False}
    job = ScanJob(id=store.new_scan_id(), params=ScanParams(inventory=True, profile="sso"))
    seen = []

    def member(_s, _p, account_id, _r, _j):
        if not signed_in["now"]:
            raise scanner.sso.SSOFailure("Not signed in to 'corp'. Use Sign in first.")
        return object()

    def token(_name):
        if job.needs_sign_in:  # the console shows the prompt; the user signs in
            seen.append(job.snapshot()["needs_sign_in"])
            signed_in["now"] = True
        return {"accessToken": "t"} if signed_in["now"] else None

    monkeypatch.setattr(scanner, "member_session", member)
    monkeypatch.setattr(scanner.sso, "load_token", token)
    monkeypatch.setattr(scanner.inventory, "inventory_account", lambda *a, **k: ({"resources": {}}, []))
    doc = scanner.run_scan(job)
    assert seen and seen[0] == "corp" and job.needs_sign_in is None
    assert set(doc["inventory"]) == {"222222222222", "333333333333"}


def test_deep_scan_skips_accounts_once_nobody_signs_in(monkeypatch):
    _org(monkeypatch)
    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", lambda s, ids: {})
    monkeypatch.setattr(scanner.sso, "profile_permission_set", lambda p: ("corp", "CTO-Read"))
    monkeypatch.setattr(scanner, "SIGN_IN_WAIT_SECONDS", 0.05)
    monkeypatch.setattr(scanner, "SIGN_IN_POLL_SECONDS", 0.01)
    monkeypatch.setattr(scanner.sso, "load_token", lambda _name: None)

    def member(*_a):
        raise scanner.sso.SSOFailure("Not signed in to 'corp'. Use Sign in first.")

    monkeypatch.setattr(scanner, "member_session", member)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams(inventory=True, profile="sso")))
    assert doc["status"] == "partial" and not doc["inventory"]
    assert sum("Not signed in" in i["message"] for i in doc["issues"]) == 2


def test_spend_regions_keep_regions_billing_a_dollar_a_month():
    rows = [
        {"account_id": "a", "service": "EC2", "region": "eu-west-1", "monthly": 50.0},
        {"account_id": "a", "service": "Lambda", "region": "af-south-1", "monthly": 0.6},
        {"account_id": "a", "service": "VPC", "region": "af-south-1", "monthly": 0.6},
        {"account_id": "a", "service": "Security Hub", "region": "us-east-2", "monthly": 0.2},
        {"account_id": "a", "service": "Route 53", "region": "global", "monthly": 9.0},
        {"account_id": "b", "service": "Config", "region": "us-east-1", "monthly": 0.3},
        {"account_id": "b", "service": "Config", "region": "eu-west-2", "monthly": 0.5},
        {"account_id": "c", "service": "Route 53", "region": "global", "monthly": 2.0},
    ]
    # Spend adds up across services; an account under the bar keeps its busiest region; no regional spend: none.
    assert scanner.spend_regions(rows) == {"a": ["eu-west-1", "af-south-1"], "b": ["eu-west-2"]}


def test_deep_scan_of_regions_with_spend(monkeypatch):
    _org(monkeypatch)
    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", lambda s, ids: {})
    monkeypatch.setattr(scanner, "member_session", lambda s, pr, a, r, j: object())
    rows = [{"account_id": "222222222222", "service": "AWS Lambda", "region": "eu-west-1", "monthly": 10.0}]
    monkeypatch.setattr(scanner.cost, "fetch_region_costs", lambda s, ids, m, *_: rows)
    asked = {}

    def inv(_s, account_id, regions, dependencies=False):
        asked[account_id] = regions
        return {"resources": {}}, []

    monkeypatch.setattr(scanner.inventory, "inventory_account", inv)
    params = ScanParams(inventory=True, role_name="r", region_scope="spend")
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=params))
    # No regional spend for the second account: it is read in every region, not skipped.
    assert asked == {"222222222222": ["eu-west-1"], "333333333333": None}
    assert any("only the regions with spend" in i["message"] for i in doc["issues"])
    with pytest.raises(ValueError):
        ScanParams(region_scope="some").validate()


def test_regions_with_spend_falls_back_to_all_without_spend_by_region(monkeypatch):
    _org(monkeypatch)
    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", lambda s, ids: {})
    monkeypatch.setattr(scanner, "member_session", lambda s, pr, a, r, j: object())
    asked = []
    monkeypatch.setattr(
        scanner.inventory, "inventory_account", lambda _s, a, regions, **k: (asked.append(regions), ({}, []))[1]
    )
    params = ScanParams(inventory=True, role_name="r", region_scope="spend")
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=params))
    assert asked == [None, None]
    assert any(i["severity"] == "warning" and "every region" in i["message"] for i in doc["issues"])


def test_a_stopped_scan_ends_cancelled_and_saves_nothing(monkeypatch):
    from exitrisk import scanner

    saved = []
    monkeypatch.setattr(scanner.store, "save_scan", saved.append)

    def run(job):
        job.update("cost", 10, "reading")
        job.cancel()
        job.update("cost", 20, "never shown")  # the next progress step stops it
        raise AssertionError("not reached")

    monkeypatch.setattr(scanner, "run_scan", run)
    job = scanner.ScanJob(id="x", params=scanner.ScanParams(profile=None))
    scanner._run_safely(job)
    assert job.status == "cancelled" and job.phase == "cancelled" and not saved


def test_pmap_starts_no_more_items_after_a_failure():
    from exitrisk.parallel import pmap

    started = []

    def fn(x):
        started.append(x)
        if x == 0:
            raise ValueError("boom")
        import time

        time.sleep(0.05)
        return x

    with pytest.raises(ValueError):
        pmap(fn, range(40), workers=2)
    assert len(started) < 40
