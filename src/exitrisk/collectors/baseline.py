"""The landing-zone baseline: what AWS itself puts in every account and region, part of no workload.

Control Tower, Amazon Inspector and Security Incident Response each deploy the same EventBridge rules,
SNS topics, Lambda functions and CloudFormation stacks into every account and every region. On a
166-account estate they made half the integrations a dependency scan counted (23,600 of 46,758), and
none of it is work an exit has to rebuild: the target platform brings its own guard rails. So the
inventory and the dependency scan leave it out, and the scan says how much it left out.

Only what AWS names or marks as its own is left out: a rule with ``ManagedBy`` set (created by an AWS
service), and names AWS reserves for Control Tower and Inspector. A platform team's own baseline
(patching, monitoring agents) is still counted, as the scan cannot tell it from a workload by name.
"""

from __future__ import annotations

# Names AWS gives the resources Control Tower and Amazon Inspector deploy. No workload starts with these.
PREFIXES = (
    "aws-controltower-",
    "AWSControlTower",
    "StackSet-AWSControlTower",
    "DO-NOT-DELETE-AmazonInspector",
)

# AWS security and governance services as the target of an integration ("eventbridge>inspector2"):
# a rule that feeds Inspector or Control Tower is the service's own plumbing. Used for scans saved
# before the baseline was left out at collection.
PLATFORM_TARGETS = ("inspector2", "security-ir", "controltower", "guardduty", "securityhub", "config", "autoscaling")


def is_baseline(name: str | None) -> bool:
    """True for a resource name (or the last part of an ARN) that AWS uses for its own baseline."""
    return bool(name) and name.rsplit(":", 1)[-1].startswith(PREFIXES)


def managed_rule(rule: dict) -> bool:
    """An EventBridge rule an AWS service created (ManagedBy set) or Control Tower deployed."""
    return bool(rule.get("ManagedBy")) or is_baseline(rule.get("Name"))


def platform_edge(edge: str) -> bool:
    """'eventbridge>inspector2' and 'eventbridge>controltower-eu-west-1' are AWS's own wiring."""
    target = edge.partition(">")[2]
    return any(target == t or target.startswith(t + "-") for t in PLATFORM_TARGETS)
