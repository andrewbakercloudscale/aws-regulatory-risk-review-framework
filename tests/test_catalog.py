from pathlib import Path

import pytest

from exitrisk.catalog import Catalog, CatalogError, load_catalog


def test_catalog_loads_and_is_complete():
    cat = load_catalog()
    assert len(cat.services) > 80
    for s in cat.services:
        assert 1 <= s.tier <= 5
        assert s.why and s.migration and s.duration
        if not s.excluded:
            assert s.effort_weeks > 0, s.service
            assert s.targets, f"{s.service} has no target equivalents"


@pytest.mark.parametrize(
    "name,tier",
    [
        ("Amazon Elastic Kubernetes Service", 1),
        ("Amazon Elastic Container Service for Kubernetes", 1),  # alias
        ("Amazon Relational Database Service", 2),
        ("AWS Lambda", 4),
        ("Amazon Redshift", 4),
        ("Amazon DynamoDB", 5),
        ("amazon dynamodb", 5),  # case-insensitive
    ],
)
def test_known_tiers(name, tier):
    assert load_catalog().lookup(name).tier == tier


def test_unknown_service_is_moderate_and_flagged():
    info = load_catalog().lookup("Amazon Brand New Thing")
    assert info.tier == 3
    assert info.classified is False
    assert info.display == "Brand New Thing"


def test_duplicate_names_rejected():
    raw = {
        "tiers": {1: {"label": "P", "score": 10}},
        "unclassified": {"tier": 3, "why": "", "migration": "", "effort_weeks": 1, "duration": ""},
        "services": [
            {
                "service": "A",
                "display": "A",
                "category": "c",
                "tier": 1,
                "why": "w",
                "migration": "m",
                "effort_weeks": 1,
                "duration": "d",
            },
            {
                "service": "B",
                "aliases": ["A"],
                "display": "B",
                "category": "c",
                "tier": 1,
                "why": "w",
                "migration": "m",
                "effort_weeks": 1,
                "duration": "d",
            },
        ],
    }
    with pytest.raises(CatalogError):
        Catalog(raw)


def test_billing_lines_excluded():
    cat = load_catalog()
    assert cat.lookup("Tax").excluded
    assert cat.lookup("AWS Support (Enterprise)").excluded


def test_lifecycle_notes_and_recent_additions():
    cat = load_catalog()
    assert "30 October 2026" in cat.lookup("Amazon Pinpoint").why
    assert "30 September 2026" in cat.lookup("AWS App Mesh").why
    assert "reopened" in cat.lookup("AWS CodeCommit").why
    for svc, tier in [
        ("AWS Elastic Disaster Recovery", 2),
        ("AWS Fault Injection Simulator", 2),
        ("AWS Payment Cryptography", 4),
        ("AWS CloudShell", 1),
    ]:
        info = cat.lookup(svc)
        assert info.classified and info.tier == tier, svc


def test_every_service_rates_how_much_ai_agents_help():
    cat = load_catalog()
    raw = (Path(__file__).resolve().parents[1] / "src/exitrisk/data/service_catalog.yaml").read_text()
    assert raw.count("    agentic: ") == len(cat.services)  # rated on purpose, not by the default
    for name, rating in [
        ("AWS Lambda", "high"),
        ("Amazon API Gateway", "high"),
        ("AWS Step Functions", "high"),
        ("AWS CloudFormation", "high"),
        ("Amazon Elastic File System", "none"),
        ("Amazon DynamoDB", "low"),
    ]:
        assert cat.lookup(name).agentic == rating, name
    assert all(s.agentic == "none" for s in cat.services if s.excluded)


def test_bad_agentic_rating_rejected():
    raw = {
        "tiers": {1: {"label": "Portable", "score": 10}},
        "unclassified": {"tier": 3, "why": "x", "migration": "y", "effort_weeks": 1, "duration": "z"},
        "services": [
            {
                "service": "S",
                "display": "S",
                "category": "C",
                "tier": 1,
                "why": "w",
                "migration": "m",
                "effort_weeks": 1,
                "duration": "d",
                "agentic": "magic",
            }
        ],
    }
    with pytest.raises(CatalogError, match="agentic"):
        Catalog(raw)
