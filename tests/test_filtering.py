import pytest

from exitrisk.filtering import AccountFilter, FilterError


def test_empty_filter_matches_all():
    f = AccountFilter()
    assert not f.active and f.matches("anything")


@pytest.mark.parametrize(
    "mode,pattern,name,expected",
    [
        ("contains", "prod", "payments-prod", True),
        ("contains", "prod", "payments-PROD", True),
        ("contains", "prod,prd", "cards-prd-01", True),
        ("contains", "prod", "payments-uat", False),
        ("prefix", "prd-", "prd-payments", True),
        ("prefix", "prd-", "payments-prd-", False),
        ("suffix", "-prod", "payments-prod", True),
        ("regex", r"^(prd|prod)-\d+$", "prod-42", True),
        ("contains", "a.b", "axb", False),  # literal, not regex
    ],
)
def test_modes(mode, pattern, name, expected):
    assert AccountFilter(include=pattern, mode=mode).matches(name) is expected


def test_exclude_wins():
    f = AccountFilter(include="prod", exclude="sandbox")
    assert f.matches("app-prod")
    assert not f.matches("sandbox-prod")


def test_bad_regex_and_mode():
    with pytest.raises(FilterError):
        AccountFilter(include="(", mode="regex")
    with pytest.raises(FilterError):
        AccountFilter(mode="glob")


def test_describe():
    assert "prod" in AccountFilter(include="prod").describe()
