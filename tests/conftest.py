import os
import tempfile

# Isolate every test run from the user's real ~/.exitrisk before exitrisk is imported.
os.environ["EXITRISK_DATA_DIR"] = tempfile.mkdtemp(prefix="exitrisk-test-")
# Deep scans read accounts in the test process, where the tests' fakes are; test_procs.py covers workers.
os.environ["EXITRISK_PROCESSES"] = "1"

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _online(monkeypatch):
    """Tests never probe the real network: online unless a test says otherwise."""
    from exitrisk import network

    monkeypatch.setattr(network, "online", lambda: True)


@pytest.fixture(autouse=True)
def _no_zscaler_feed(monkeypatch):
    """Zscaler's published ranges come from the internet: tests give their own."""
    from exitrisk import zscaler

    monkeypatch.setattr(zscaler, "ranges", lambda: ["165.225.0.0/17"])


@pytest.fixture(autouse=True)
def _fresh_ou_tree_cache():
    """The OU tree cache lives for the process; one test's fake organisation must not leak into the next."""
    from exitrisk.collectors import organizations

    organizations.clear_tree_cache()
    yield
