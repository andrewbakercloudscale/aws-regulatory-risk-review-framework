"""End of life software and container image supply, for the Outage Risk Report.

End of life: a version AWS or its vendor no longer supports is a change that will be forced, on a
date someone else chose, and fixes that cannot be had in an incident. Dates come from AWS's own APIs
where it publishes them (RDS and Aurora, EKS, MSK); for operating systems, from the vendors' published
end of support dates, below, matched against the exact name and version Systems Manager reports. An
instance Systems Manager does not manage is counted, never guessed at from its image name.

Container images: a workload whose images come from a registry outside AWS cannot restart, scale out
or move to a new node while that registry, or the path to it, is down. Kubernetes is read with the
scan identity's access entry; ECS from its task definitions and the tasks it stopped.

Imported at the end of collectors/outage.py, and adds its tasks and metrics to that module's.
"""

from __future__ import annotations

import re
import threading
from datetime import date

from .assurance import _pages
from .outage import MAX_ITEMS, METRICS, REGION_TASKS, OutageCtx

SOON_DAYS = 180  # support ending this soon is worth planning for now
FORCED_DAYS = 180  # a major upgrade AWS forces this soon is high: too little time to test it and dodge the peak
EKS_AUTO_DAYS = 60  # an EKS control plane AWS upgrades itself this soon is high
EKS_NOTICE_DAYS = 90  # paid Extended Support starting this soon, worth a low note
CEILING_HOURS = 24  # hours at the maximum in the lookback window before it is worth a look
SATURATED_HOURS = 7  # hours also at full CPU there: it ran out, not just reached its ceiling
MAX_TASK_DEFS = 300  # ECS task definitions read per region
MAX_STOPPED = 100  # stopped ECS tasks read per cluster: ECS keeps them about an hour

# Hourly maxima, for capacity that reaches its ceiling in bursts the hourly average hides.
_RDS = "Amazon Relational Database Service"
METRICS.update(
    {
        "rds_acu_max": ("AWS/RDS", ("DBInstanceIdentifier",), "ACUUtilization", "Maximum", _RDS),
        "rds_cpu_max": ("AWS/RDS", ("DBInstanceIdentifier",), "CPUUtilization", "Maximum", _RDS),
    }
)

# Operating systems: (name pattern, version pattern or None, end of support, what ends). The vendors'
# published dates for standard support: paid extended support (Windows ESU, RHEL ELS, Ubuntu Pro) can
# run later, and is named in the finding rather than assumed.
OS_EOL = [
    (r"Windows Server 2008", None, "2020-01-14", "Microsoft extended support"),
    (r"Windows Server 2012", None, "2023-10-10", "Microsoft extended support"),
    (r"Windows Server 2016", None, "2027-01-12", "Microsoft extended support"),
    (r"Windows Server 2019", None, "2029-01-09", "Microsoft extended support"),
    (r"^Amazon Linux AMI$", None, "2023-12-31", "AWS support for Amazon Linux (2018.03)"),
    (r"^Amazon Linux$", r"^2$", "2026-06-30", "AWS support for Amazon Linux 2"),
    (r"^Amazon Linux$", r"^2018", "2023-12-31", "AWS support for Amazon Linux (2018.03)"),
    (r"^CentOS", r"^7", "2024-06-30", "CentOS Linux 7 updates"),
    (r"^CentOS", r"^8", "2021-12-31", "CentOS Linux 8 updates"),
    (r"^Red Hat Enterprise Linux", r"^6", "2020-11-30", "Red Hat maintenance support"),
    (r"^Red Hat Enterprise Linux", r"^7", "2024-06-30", "Red Hat maintenance support"),
    (r"^Oracle Linux", r"^6", "2021-03-01", "Oracle Premier Support"),
    (r"^Oracle Linux", r"^7", "2024-12-31", "Oracle Premier Support"),
    (r"^Ubuntu", r"^14\.04", "2019-04-30", "Canonical standard support"),
    (r"^Ubuntu", r"^16\.04", "2021-04-30", "Canonical standard support"),
    (r"^Ubuntu", r"^18\.04", "2023-05-31", "Canonical standard support"),
    (r"^Ubuntu", r"^20\.04", "2025-05-31", "Canonical standard support"),
    (r"^Ubuntu", r"^22\.04", "2027-06-30", "Canonical standard support"),
    (r"^Debian", r"^9", "2022-06-30", "Debian LTS"),
    (r"^Debian", r"^10", "2024-06-30", "Debian LTS"),
    (r"^Debian", r"^11", "2026-08-31", "Debian LTS"),
    (r"^SLES|SUSE Linux Enterprise Server", r"^12", "2024-10-31", "SUSE general support"),
]

# ElastiCache: AWS moved Redis OSS 4 and 5 to paid Extended Support; no API publishes the dates.
CACHE_EXTENDED = re.compile(r"^[45]\.")
# EKS node groups on Amazon Linux 2 images: AWS publishes none for Kubernetes 1.33 and later.
AL2_AMI = re.compile(r"^AL2_")

ECR_HOST = re.compile(r"^(\d{12}\.dkr\.ecr(?:-fips)?\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?|public\.ecr\.aws)$")
PULL_FAILED = ("ImagePullBackOff", "ErrImagePull", "InvalidImageName")


def registry(image: str) -> str:
    """The registry host of an image reference, as a container runtime resolves it."""
    first, _, rest = image.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        return first.lower()
    return "docker.io"


def is_ecr(host: str) -> bool:
    return bool(ECR_HOST.match(host))


def pulls_every_start(image: str, policy: str | None) -> bool:
    """True when a pod start always goes to the registry: Always, or the Kubernetes default for an image
    with no tag or the latest tag. An image pinned by digest is never pulled again for a node that has it."""
    if "@sha256:" in image:
        return policy == "Always"
    if policy:
        return policy == "Always"
    name = image.rsplit("/", 1)[-1]
    return ":" not in name or name.endswith(":latest")


def _days(until: str | date, today: date) -> int:
    return ((date.fromisoformat(until) if isinstance(until, str) else until) - today).days


def _ends(day) -> str:
    return day.date().isoformat() if hasattr(day, "date") else str(day)[:10]


# ------------------------------------------------------------------------------------------------ databases
_MAJORS_LOCK = threading.Lock()


def _majors(ctx: OutageCtx, rds, region: str, engine: str) -> list[dict]:
    """AWS's support dates for each major version of an engine in the region, read once per scan."""
    cache = ctx.__dict__.setdefault("_majors", {})
    with _MAJORS_LOCK:
        if (region, engine) in cache:
            return cache[(region, engine)]
    found = _pages(rds, "describe_db_major_engine_versions", "DBMajorEngineVersions", Engine=engine)
    with _MAJORS_LOCK:
        cache[(region, engine)] = found
    return found


def major_of(version: str, majors: list[str]) -> str | None:
    """The major version a full version belongs to: 17.9 is 17, 8.0.mysql_aurora.3.04.0 is 8.0."""
    hits = [m for m in majors if version == m or version.startswith(m + ".")]
    return max(hits, key=len) if hits else None


def judge_db_support(version: str, lifecycles: list[dict], extended_on: bool, today: date) -> tuple[str, str] | None:
    """(severity, why) for a database engine's support, or None when nothing is due."""
    dates = {lc.get("LifecycleSupportName", ""): lc for lc in lifecycles}
    std = dates.get("open-source-rds-standard-support")
    ext = dates.get("open-source-rds-extended-support")
    if not std or not std.get("LifecycleSupportEndDate"):
        return None
    std_end = _ends(std["LifecycleSupportEndDate"])
    ext_end = _ends(ext["LifecycleSupportEndDate"]) if ext and ext.get("LifecycleSupportEndDate") else None
    left = _days(std_end, today)
    if left < 0:
        if ext_end and extended_on:
            to_force = _days(ext_end, today)
            sev = "high" if to_force <= FORCED_DAYS else "medium"
            return sev, (
                f"{version}: standard support ended {std_end}; in paid RDS Extended Support, and AWS upgrades it "
                f"to a new major version on {ext_end} whether it is ready or not"
            )
        return "high", f"{version}: standard support ended {std_end}; AWS upgrades it to a new major version"
    if left <= SOON_DAYS:
        if extended_on and ext_end:
            return "medium", (
                f"{version}: standard support ends {std_end}; then paid RDS Extended Support until {ext_end}"
            )
        sev = "high" if left <= FORCED_DAYS else "medium"
        return sev, f"{version}: standard support ends {std_end}, when AWS upgrades it to a new major version"
    return None


def task_db_lifecycle(ctx: OutageCtx, region: str) -> None:
    rds = ctx.client("rds", region)
    today = ctx.now.date()
    seen: set[str] = set()
    instances = _pages(rds, "describe_db_instances", "DBInstances", cap=MAX_ITEMS)
    for d in instances:
        _acu_ceiling(ctx, d, region)
        engine, version = d.get("Engine", ""), d.get("EngineVersion", "")
        res = d.get("DBClusterIdentifier") or d["DBInstanceIdentifier"]  # an Aurora cluster has one version
        if res in seen or not engine.startswith(("postgres", "mysql", "mariadb", "aurora")):
            continue
        seen.add(res)
        majors = _majors(ctx, rds, region, engine)
        major = major_of(version, [m["MajorEngineVersion"] for m in majors])
        if not major:
            continue
        lifecycles = next(m for m in majors if m["MajorEngineVersion"] == major).get("SupportedEngineLifecycles") or []
        extended_on = d.get("EngineLifecycleSupport", "open-source-rds-extended-support").endswith("extended-support")
        got = judge_db_support(f"{engine} {version}", lifecycles, extended_on, today)
        if got:
            ctx.add("db_eol", res, region, sev=got[0], note=got[1])
    ctx.r.ok("eol_db")


def _acu_ceiling(ctx: OutageCtx, d: dict, region: str) -> None:
    """Aurora Serverless that reaches its maximum ACUs in bursts: the hourly average hides them."""
    if d.get("DBInstanceClass") != "db.serverless":
        return
    name = d["DBInstanceIdentifier"]
    m = ctx.metrics(region)
    acu, cpu = m["rds_acu_max"].get(name), m["rds_cpu_max"].get(name)
    if not acu or not acu.n or acu.hot < CEILING_HOURS:
        return
    full = cpu.hot if cpu and cpu.n else 0
    note = f"at its maximum ACUs in {acu.hot:,} of {acu.n:,} hours (hourly maximum)"
    if full >= SATURATED_HOURS:
        note += f"; CPU at the limit in {full:,} of them, so it ran out of capacity, not just reached it"
    ctx.add(
        "aurora_acu_ceiling",
        name,
        region,
        sev="high" if full >= SATURATED_HOURS else "medium",
        note=note,
    )


def task_cache_lifecycle(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("elasticache", region)
    seen: set[str] = set()
    for c in _pages(client, "describe_cache_clusters", "CacheClusters", cap=MAX_ITEMS):
        res = c.get("ReplicationGroupId") or c["CacheClusterId"]
        if res in seen:
            continue
        seen.add(res)
        if c.get("Engine") == "redis" and CACHE_EXTENDED.match(c.get("EngineVersion") or ""):
            ctx.add(
                "cache_eol",
                res,
                region,
                note=f"Redis OSS {c['EngineVersion']}: in paid ElastiCache Extended Support, then upgraded by AWS",
            )
    ctx.r.ok("eol_cache")


def task_msk_lifecycle(ctx: OutageCtx, region: str) -> None:
    client = ctx.client("kafka", region)
    clusters = _pages(client, "list_clusters_v2", "ClusterInfoList")
    if not clusters:
        ctx.r.ok("eol_msk")
        return
    status = {v["Version"]: v.get("Status") for v in _pages(client, "list_kafka_versions", "KafkaVersions")}
    for c in clusters:
        version = ((c.get("Provisioned") or {}).get("CurrentBrokerSoftwareInfo") or {}).get("KafkaVersion")
        if version and status.get(version) == "DEPRECATED":
            ctx.add("msk_eol", c["ClusterName"], region, note=f"Kafka {version}: AWS has deprecated it")
    ctx.r.ok("eol_msk")


# ------------------------------------------------------------------------------------------------ EKS
def judge_eks_support(version: str, info: dict, policy: str, today: date) -> tuple[str, str] | None:
    """(severity, why) for a cluster's Kubernetes version, from describe_cluster_versions, or None."""
    std, ext = info.get("endOfStandardSupportDate"), info.get("endOfExtendedSupportDate")
    if not std:
        return None
    std_end, ext_end = _ends(std), (_ends(ext) if ext else None)
    left = _days(std_end, today)
    if left < 0 and ext_end:
        to_force = _days(ext_end, today)
        return ("high" if to_force <= FORCED_DAYS else "medium"), (
            f"Kubernetes {version}: standard support ended {std_end}; in paid Extended Support, and AWS upgrades "
            f"the control plane on {ext_end}"
        )
    if left <= SOON_DAYS:
        if policy == "STANDARD":
            return ("high" if left <= EKS_AUTO_DAYS else "medium"), (
                f"Kubernetes {version}: standard support ends {std_end}, when AWS upgrades the control plane "
                "(upgrade policy STANDARD)"
            )
        if left > EKS_NOTICE_DAYS:
            return None  # nothing is forced for another year: a cost to plan for, not an outage risk
        return (
            "low",
            f"Kubernetes {version}: standard support ends {std_end}; then paid Extended Support until {ext_end}",
        )
    return None


def task_eks_lifecycle(ctx: OutageCtx, region: str) -> None:
    eks = ctx.client("eks", region)
    today = ctx.now.date()
    names = _pages(eks, "list_clusters", "clusters")
    versions: dict[str, dict] = {}
    for name in names:
        c = eks.describe_cluster(name=name)["cluster"]
        version = c.get("version") or ""
        if version not in versions:
            got = eks.describe_cluster_versions(clusterVersions=[version]).get("clusterVersions") or []
            versions[version] = got[0] if got else {}
        policy = (c.get("upgradePolicy") or {}).get("supportType") or "EXTENDED"
        judged = judge_eks_support(version, versions[version], policy, today)
        if judged:
            ctx.add("eks_eol", name, region, sev=judged[0], note=judged[1])
        for g in _pages(eks, "list_nodegroups", "nodegroups", clusterName=name):
            ng = eks.describe_nodegroup(clusterName=name, nodegroupName=g)["nodegroup"]
            if AL2_AMI.match(ng.get("amiType") or ""):
                ctx.add("eks_al2_nodes", f"{name}/{g}", region, note=f"{ng['amiType']}, Kubernetes {ng.get('version')}")
    ctx.r.ok("eol_eks")


# ------------------------------------------------------------------------------------------------ operating systems
def os_end(platform: str, version: str) -> tuple[str, str] | None:
    """(end of support, what ends) for an operating system as Systems Manager names it, or None."""
    for name, ver, ends, what in OS_EOL:
        if re.search(name, platform or "") and (ver is None or re.search(ver, version or "")):
            return ends, what
    return None


def task_os_lifecycle(ctx: OutageCtx, region: str) -> None:
    ssm = ctx.client("ssm", region)
    today = ctx.now.date()
    managed = _pages(ssm, "describe_instance_information", "InstanceInformationList", cap=MAX_ITEMS * 5)
    running: dict[str, str] = {}  # instance id: its Name tag, or the id
    for r in _pages(ctx.client("ec2", region), "describe_instances", "Reservations",
                    Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):  # fmt: skip
        for inst in r.get("Instances") or []:
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags") or []}
            running[inst["InstanceId"]] = tags.get("Name") or inst["InstanceId"]
    groups: dict[tuple[str, str, str], list[str]] = {}
    for i in managed:
        if i.get("ResourceType", "EC2Instance") != "EC2Instance" or i.get("PingStatus") == "Inactive":
            continue
        platform, version = i.get("PlatformName") or "", i.get("PlatformVersion") or ""
        end = os_end(platform, version)
        if not end or _days(end[0], today) > SOON_DAYS:
            continue
        label = f"{platform} {version}".strip()
        groups.setdefault((label, *end), []).append(running.get(i["InstanceId"]) or i["InstanceId"])
    for (label, ends, what), hosts in groups.items():
        past = _days(ends, today) < 0
        shown = ", ".join(sorted(hosts)[:5]) + (f" and {len(hosts) - 5:,} more" if len(hosts) > 5 else "")
        ctx.add(
            "os_eol",
            f"{label} ({len(hosts):,} instance{'s' if len(hosts) != 1 else ''})",
            region,
            used=len(hosts),
            unit="instances",
            sev="medium" if past else "low",
            note=f"{what} {'ended' if past else 'ends'} {ends}: {shown}",
        )
    seen = {i["InstanceId"] for i in managed}
    ctx.r.fact("os_unknown", sum(1 for iid in running if iid not in seen), region)
    ctx.r.ok("eol_os")


# ------------------------------------------------------------------------------------------------ ECS images
def task_ecs_images(ctx: OutageCtx, region: str) -> None:
    ecs = ctx.client("ecs", region)
    defs: dict[str, list[str]] = {}
    by_cluster: dict[str, dict[str, set[str]]] = {}
    for arn in _pages(ecs, "list_clusters", "clusterArns"):
        cluster = arn.rsplit("/", 1)[-1]
        names = _pages(ecs, "list_services", "serviceArns", cap=MAX_ITEMS, cluster=arn)
        for at in range(0, len(names), 10):
            for svc in ecs.describe_services(cluster=arn, services=names[at : at + 10]).get("services") or []:
                td = svc.get("taskDefinition")
                if not td or not svc.get("desiredCount"):
                    continue
                if td not in defs and len(defs) < MAX_TASK_DEFS:
                    got = ecs.describe_task_definition(taskDefinition=td)["taskDefinition"]
                    defs[td] = [c.get("image", "") for c in got.get("containerDefinitions") or []]
                for image in defs.get(td, []):
                    host = registry(image)
                    if not is_ecr(host):
                        by_cluster.setdefault(cluster, {}).setdefault(host, set()).add(svc["serviceName"])
        stopped = _pages(ecs, "list_tasks", "taskArns", cap=MAX_STOPPED, cluster=arn, desiredStatus="STOPPED")
        failed: dict[str, int] = {}
        for at in range(0, len(stopped), 100):
            for t in ecs.describe_tasks(cluster=arn, tasks=stopped[at : at + 100]).get("tasks") or []:
                why = " ".join(
                    [t.get("stoppedReason") or ""] + [c.get("reason") or "" for c in t.get("containers") or []]
                )
                if "CannotPullContainer" in why or "pull image" in why.lower():
                    group = (t.get("group") or "").removeprefix("service:") or "tasks"
                    failed[group] = failed.get(group, 0) + 1
        for group, n in failed.items():
            note = f"{n:,} task(s) stopped in the last hour or so because the image could not be pulled"
            ctx.add("image_pull_failing", f"{cluster}/{group}", region, used=n, unit="tasks stopped", note=note)
    for cluster, hosts in by_cluster.items():
        services = {s for names in hosts.values() for s in names}
        ctx.add(
            "image_registry_outside",
            cluster,
            region,
            used=len(services),
            unit="services",
            note="; ".join(f"{h}: {len(n):,} service(s)" for h, n in sorted(hosts.items(), key=lambda x: -len(x[1]))),
        )
    ctx.r.ok("images")


REGION_TASKS.extend(
    [
        ("database end of life", ("eol_db",), task_db_lifecycle, ("Amazon Relational Database Service",)),
        ("elasticache end of life", ("eol_cache",), task_cache_lifecycle, ("Amazon ElastiCache",)),
        ("msk end of life", ("eol_msk",), task_msk_lifecycle, ("Amazon Managed Streaming for Apache Kafka",)),
        (
            "eks end of life",
            ("eol_eks",),
            task_eks_lifecycle,
            ("Amazon Elastic Kubernetes Service", "Amazon Elastic Container Service for Kubernetes"),
        ),
        ("operating system end of life", ("eol_os",), task_os_lifecycle, None),
        ("ecs images", ("images",), task_ecs_images, ("Amazon Elastic Container Service",)),
    ]
)
