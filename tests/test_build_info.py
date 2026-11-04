"""The version shown in the console's top bar."""

from exitrisk import __version__
from exitrisk.build_info import build_info


def test_build_info_names_the_version_and_a_time():
    b = build_info()
    assert b["version"] == __version__
    assert b["built_at"]  # from git in a checkout, else the package's file time
    assert isinstance(b["commits_since"], int) and b["commits_since"] >= 0
