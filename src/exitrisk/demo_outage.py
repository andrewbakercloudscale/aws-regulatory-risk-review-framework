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
        out[acct["id"]] = {
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
            "facts": {},
            "read_at": "",
            "seconds": 1.0,
        }
    return {"accounts": out}
