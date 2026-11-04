"""Synthetic outage risk measures for the demo organisation (screenshots and tests).

Deterministic for a given seed. A few accounts carry the classic pre-peak findings: an MSK cluster
filling up, a Connect instance near its concurrency quota, fixed replicas on EKS.
"""

from __future__ import annotations

import random

_SERVICES = [
    "ec2: Running On-Demand Standard instances",
    "vpc: VPCs per Region",
    "lambda: Concurrent executions",
    "kms: Cryptographic operations (symmetric) request rate",
    "rds: DB instances",
    "dynamodb: Account-level read throughput",
]


def _workloads(rng: random.Random, prod: bool) -> list[dict]:
    rows = [
        {
            "ns": "kube-system",
            "name": "coredns",
            "kind": "Deployment",
            "replicas": 2,
            "cpu_req": 100,
            "mem_req": 70,
            "mem_lim": 170,
        }
    ]
    for name in (
        "checkout",
        "statements",
        "notifications",
        "fraud-score",
        "api-gateway",
        "card-auth",
        "ledger-sync",
        "batch-runner",
    ):
        n = rng.choice([1, 2, 2, 3, 3, 4, 6])
        w = {
            "ns": "payments" if prod else "apps",
            "name": name,
            "kind": "Deployment",
            "replicas": n,
            "cpu_req": rng.choice([25, 50, 100, 250, 500]),
            "mem_req": 256,
            "mem_lim": rng.choice([128, 200, 256, 512, 1024]),
        }
        if rng.random() < 0.4:
            w.update(hpa_max=rng.choice([6, 10, 20]), current=n)
        if rng.random() < 0.1:
            w["oom"] = rng.randint(1, 4)
        rows.append(w)
    return rows


def _review_rows(rng: random.Random, name: str, region: str, prod: bool) -> tuple[list[dict], list[dict], dict]:
    """Findings and live settings for the service reviews. Invented, like the rest of the demo."""
    rows: list[dict] = []
    profiles: list[dict] = []
    res = f"{name}-db"
    conn = rng.randint(200, 1500)
    limit = 1802
    profiles.append(
        {
            "svc": "rds",
            "res": res,
            "region": region,
            "facts": {
                "Engine": "postgres 15.8",
                "Class": "db.r6g.2xlarge",
                "Multi-AZ": "yes" if prod else "no",
                "Backups, days": 7,
            },
            "stats": [
                {
                    "k": "CPU",
                    "peak": round(rng.uniform(40, 88), 1),
                    "avg": round(rng.uniform(15, 35), 1),
                    "unit": "%",
                    "limit": 100,
                },
                {"k": "Connections", "peak": conn, "avg": round(conn * 0.45), "unit": "", "limit": limit},
            ],
        }
    )
    rows.append(
        {
            "rule": "rds_connections",
            "res": res,
            "region": region,
            "pct": round(100 * conn / limit, 1),
            "used": conn,
            "limit": limit,
            "load": True,
            "note": "db.r6g.2xlarge; from parameter group default",
        }
    )
    if rng.random() < 0.4:
        rows.append(
            {
                "rule": "no_alarm",
                "res": f"rds: {res}",
                "region": region,
                "note": "no CloudWatch alarm on FreeStorageSpace",
            }
        )
    if rng.random() < 0.5:
        cache = f"{name}-cache"
        profiles.append(
            {
                "svc": "elasticache",
                "res": cache,
                "region": region,
                "facts": {"Engine": "redis", "Node": "cache.r6g.large", "Failover": "enabled" if prod else "disabled"},
                "stats": [
                    {
                        "k": "Engine CPU",
                        "peak": round(rng.uniform(20, 75), 1),
                        "avg": round(rng.uniform(5, 20), 1),
                        "unit": "%",
                        "limit": 100,
                    }
                ],
            }
        )
        if rng.random() < 0.4:
            rows.append(
                {"rule": "cache_no_failover", "res": cache, "region": region, "note": "one primary, no replica"}
            )
    if rng.random() < 0.6:
        fn = f"{name}-handler"
        ran = round(rng.uniform(4, 29), 1)
        profiles.append(
            {
                "svc": "lambda",
                "res": fn,
                "region": region,
                "facts": {"Runtime": "python3.12", "Memory": "512 MB", "Timeout": "30 s"},
                "stats": [{"k": "Longest run", "peak": ran, "avg": round(ran / 4, 1), "unit": "s", "limit": 30}],
            }
        )
        rows.append(
            {
                "rule": "lambda_timeout",
                "res": fn,
                "region": region,
                "pct": round(100 * ran / 30, 1),
                "used": ran,
                "limit": 30,
                "unit": "s",
                "load": True,
            }
        )
    if rng.random() < 0.5:
        queue = f"{name}-events"
        age = rng.randint(1000, 300000)
        profiles.append(
            {
                "svc": "sqs",
                "res": queue,
                "region": region,
                "facts": {"Retention": "4 days", "Dead-letter queue": "no"},
                "stats": [{"k": "Oldest message", "peak": age, "avg": round(age / 3), "unit": "s", "limit": 345600}],
            }
        )
        rows.append(
            {
                "rule": "sqs_backlog",
                "res": queue,
                "region": region,
                "pct": round(100 * age / 345600, 1),
                "used": age,
                "limit": 345600,
                "unit": "s",
                "load": True,
            }
        )
        rows.append({"rule": "sqs_no_dlq", "res": queue, "region": region, "note": "backlog seen"})
    if rng.random() < 0.35:
        lb = f"{name}-alb"
        profiles.append(
            {
                "svc": "elb",
                "res": lb,
                "region": region,
                "facts": {"Type": "application", "Zones": 1 if prod else 2},
                "stats": [],
            }
        )
        if prod:
            rows.append({"rule": "lb_one_az", "res": lb, "region": region, "note": "one subnet"})
            rows.append(
                {
                    "rule": "ec2_burstable",
                    "res": f"{name}-worker",
                    "region": region,
                    "type": "t3.large",
                    "baseline": 30,
                    "cpu": 24.0,
                    "unlimited": False,
                }
            )
    if rng.random() < 0.25:
        rows.append(
            {"rule": "rds_maintenance", "res": res, "region": region, "ends": "2026-11-29", "note": "system-update"}
        )
    if rng.random() < 0.2:
        rows.append(
            {
                "rule": "bedrock_throttled",
                "res": "anthropic.model",
                "region": region,
                "used": rng.randint(5, 900),
                "unit": "calls throttled",
            }
        )
    counts: dict[str, int] = {}
    for p in profiles:
        counts[p["svc"]] = counts.get(p["svc"], 0) + 1
    return rows, profiles, counts


NETWORK_ACCOUNT = "999900001111"  # the demo's shared network account, outside the scanned OU


def build(accounts: list[dict], seed: int = 21) -> dict:
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data, not security
    out: dict[str, dict] = {}
    for acct in accounts:
        if acct.get("status") != "ACTIVE" or "innovation" in acct["name"]:
            continue
        name = acct["name"]
        prod = "prod" in name
        region = rng.choice(["eu-west-1", "af-south-1"])
        rows = []
        for svc in rng.sample(_SERVICES, 3):
            pct = rng.uniform(30, 75)
            rows.append(
                {
                    "rule": "limit_account" if svc.startswith(("ec2", "vpc")) else "limit_product",
                    "res": svc,
                    "region": region,
                    "pct": round(pct, 1),
                    "used": round(pct * 10),
                    "limit": 1000,
                    "load": svc.startswith(("ec2", "lambda", "kms")),
                }
            )
        if rng.random() < 0.5:
            rows.append(
                {
                    "rule": "rds_cpu",
                    "res": f"{name}-db",
                    "region": region,
                    "pct": round(rng.uniform(35, 88), 1),
                    "load": True,
                    "note": "db.r6g.2xlarge, postgres",
                }
            )
            pct = rng.uniform(40, 85)
            rows.append(
                {
                    "rule": "rds_storage",
                    "res": f"{name}-db",
                    "region": region,
                    "pct": round(pct, 1),
                    "used": round(pct * 5),
                    "limit": 500,
                    "unit": "GiB",
                    "days": round(rng.uniform(20, 200), 1),
                    "note": "no storage autoscaling",
                }
            )
        if rng.random() < 0.3:
            rows.append(
                {
                    "rule": "rds_replica_mismatch",
                    "res": f"{name}-db-replica",
                    "region": region,
                    "note": "class db.r6g.large, source db.r6g.2xlarge",
                }
            )
        if rng.random() < 0.4:
            rows.append(
                {
                    "rule": "subnet_ips",
                    "res": f"{name}-private-a",
                    "region": region,
                    "pct": round(rng.uniform(40, 92), 1),
                    "used": 210,
                    "limit": 251,
                }
            )
        clusters = []
        if prod or "platform" in name:
            rows.append(
                {
                    "rule": "eks_subnet_ips",
                    "res": f"{name}-eks-a",
                    "region": region,
                    "pct": round(rng.uniform(45, 80), 1),
                    "used": 3000,
                    "limit": 4091,
                    "load": True,
                    "note": f"EKS cluster {name}-eks",
                }
            )
            workloads = _workloads(rng, prod)
            read = rng.random() > 0.2
            clusters.append(
                {
                    "name": f"{name}-eks",
                    "region": region,
                    "version": "1.33",
                    "access": "read" if read else "refused",
                    "nodegroups": 2,
                    **(
                        {
                            "workloads": workloads,
                            "workload_count": len(workloads),
                            "pods": 120,
                            "pending": rng.choice([0, 0, 0, 3]),
                        }
                        if read
                        else {"detail": "HTTP 401: this identity has no access entry on the cluster"}
                    ),
                }
            )
        if "payment" in name or "data" in name:
            pct = rng.uniform(55, 88)
            rows += [
                {
                    "rule": "msk_disk",
                    "res": f"{name}-events",
                    "region": region,
                    "pct": round(pct, 1),
                    "days": round(rng.uniform(12, 70), 1),
                    "note": "m5.2xlarge, 6 brokers, 2000 GiB each",
                },
                {
                    "rule": "msk_cpu",
                    "res": f"{name}-events",
                    "region": region,
                    "pct": round(rng.uniform(35, 65), 1),
                    "load": True,
                    "note": "m5.2xlarge; AWS advises staying under 60%",
                },
                {"rule": "msk_no_autoscale", "res": f"{name}-events", "region": region, "note": "2000 GiB per broker"},
            ]
        if "customer" in name or "contact" in name or "payment" in name:
            rows += [
                {
                    "rule": "limit_connect",
                    "res": f"{name}-connect: concurrent calls",
                    "region": region,
                    "pct": round(rng.uniform(45, 82), 1),
                    "load": True,
                },
                {
                    "rule": "limit_s3",
                    "res": "General purpose buckets in the account",
                    "region": "global",
                    "pct": 81.0,
                    "used": 81,
                    "limit": 100,
                },
            ]
        if rng.random() < 0.15:
            rows.append(
                {
                    "rule": "nat_port_errors",
                    "res": f"nat-0{rng.randint(1000, 9999)}",
                    "region": region,
                    "used": rng.randint(20, 4000),
                    "unit": "in the lookback window",
                }
            )
        if prod and rng.random() < 0.3:
            rows.append({"rule": "resolver_rule_one_target", "res": f"corp.example ({name})", "region": region,
                         "note": "forwards to 10.10.0.53 only"})  # fmt: skip
        if prod and rng.random() < 0.2:
            rows.append({"rule": "tgw_one_az", "res": f"tgw-attach-{rng.randint(1000, 9999)}", "region": region,
                         "note": "attached in one zone only; the VPC has subnets in 3 zones"})  # fmt: skip
        extra, profiles, counts = _review_rows(rng, name, region, prod)
        for c in clusters:
            counts["eks"] = counts.get("eks", 0) + 1
            profiles.append(
                {
                    "svc": "eks",
                    "res": c["name"],
                    "region": c["region"],
                    "facts": {
                        "Kubernetes": c.get("version", ""),
                        "Workloads": c.get("workload_count", len(c.get("workloads") or [])),
                    },
                    "stats": [],
                }
            )
        rows += extra
        out[acct["id"]] = {
            "profiles": profiles,
            "profile_counts": counts,
            "rows": rows,
            "rows_cut": 0,
            "clusters": clusters,
            "quota_values": {},
            "compared": rng.randint(150, 420),
            "regions": [region],
            "checks": {
                k: {"status": "pass", "note": ""}
                for k in ("limits", "s3_limits", "connect", "fixed", "storage", "msk", "eks", "network", "certificates")
            },
            "facts": {
                "depends_on": {
                    region: [
                        {"owner": NETWORK_ACCOUNT, "what": "Transit gateway", "detail": "tgw-0demo"},
                        {"owner": NETWORK_ACCOUNT, "what": "DNS forwarding rules", "detail": "corp.example"},
                    ]
                }
            },
            "read_at": "",
            "seconds": 1.0,
        }
    return {"accounts": out}
