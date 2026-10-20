import os
import tempfile

# Isolate every test run from the user's real ~/.exitrisk before exitrisk is imported.
os.environ["EXITRISK_DATA_DIR"] = tempfile.mkdtemp(prefix="exitrisk-test-")
