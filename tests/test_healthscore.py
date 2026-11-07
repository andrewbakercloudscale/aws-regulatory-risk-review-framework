from datetime import datetime, timedelta, timezone

from exitrisk import healthscore as S
from exitrisk.collectors import healthcheck_deep as D

NOW = datetime(2026, 11, 7, tzinfo=timezone.utc)
SINCE = NOW - timedelta(days=14)
OLD = NOW - timedelta(days=90)


def days(v):
    return [(NOW - timedelta(days=i), v) for i in range(14)]


def db(name, **kw):
    return {"DBInstanceIdentifier": name, "DBInstanceStatus": "available", "InstanceCreateTime": OLD,
            "Engine": "postgres", "DBInstanceClass": "db.r6g.large", **kw}  # fmt: skip


def test_clean_account_is_green_100():
    h = S.score_account([], [], [], [])
    assert h["score"] == 100 and h["rag"] == "green"
    assert sum(p["weight"] for p in h["parts"]) == 100


def test_live_critical_forces_red():
    h = S.score_account([{"title": "LB down", "severity": "critical"}], [], [], [])
    assert h["rag"] == "red" and h["score"] >= 80
    h = S.score_account([{"title": "LB slow", "severity": "high"}], [], [], [])
    assert h["rag"] == "amber"


def test_parts_and_grouping():
    risks = [{"rule": "ec2_old_gen", "area": "hardware", "severity": "medium"}] * 40
    h = S.score_account([], risks, [], [])
    cur = next(p for p in h["parts"] if p["key"] == "currency")
    assert cur["issues"] == 40 and 0 < cur["score"] < 15
    assert "×40" in cur["top"][0]["title"]
    assert S.risk_part({"rule": "db_eol", "area": "lifecycle"}) == "currency"
    assert S.risk_part({"rule": "limit_product", "area": "limits"}) == "capacity"
    assert S.risk_part({"rule": "rds_single_az", "area": "storage"}) == "resilience"
    assert S.risk_part({"rule": "rds_replica_idle", "area": "usage"}) == "usage"
    assert S.signal_part({"chronic": True, "title": "Quota near its limit"}) == "capacity"
    assert S.signal_part({"chronic": True, "title": "Route blackhole"}) == "standing"


def test_idle_plain_replica_found_cross_region_skipped():
    dbs = [db("src"), db("rep", ReadReplicaSourceDBInstanceIdentifier="src"),
           db("dr", ReadReplicaSourceDBInstanceIdentifier="arn:aws:rds:eu-west-1:111111111111:db:src"),
           db("busy", ReadReplicaSourceDBInstanceIdentifier="src"),
           db("new", ReadReplicaSourceDBInstanceIdentifier="src", InstanceCreateTime=NOW - timedelta(3))]  # fmt: skip
    conns = {"rep": days(0), "dr": days(0), "busy": days(25), "new": days(0)}
    out = D.replica_findings(dbs, conns, {}, "af-south-1", SINCE)
    assert [f["res"] for f in out] == ["rep"]


def test_aurora_keeps_one_failover_reader_and_flags_hot_writer():
    a = {"Engine": "aurora-postgresql", "DBClusterIdentifier": "c1"}
    dbs = [db("w", _writer=True, **a), db("r1", _writer=False, PromotionTier=1, **a),
           db("r2", _writer=False, PromotionTier=2, **a)]  # fmt: skip
    out = D.replica_findings(dbs, {"r1": days(0), "r2": days(0), "w": days(300)}, {"w": days(75)}, "x", SINCE)
    assert sorted(f["rule"] for f in out) == ["aurora_reads_on_writer", "rds_replica_idle"]
    assert next(f for f in out if f["rule"] == "rds_replica_idle")["res"] == "r2"
    # one reader alone is the failover target, and a quiet writer needs no relief
    out = D.replica_findings(dbs[:2], {"r1": days(0)}, {"w": days(20)}, "x", SINCE)
    assert out == []
