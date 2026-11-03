"""Run RPC request regressions with network blocked and no inherited keys."""
import logging
import os
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
for name in list(os.environ):
    if any(part in name.upper() for part in ("API_KEY", "RPC_URL", "HISTORY_TOKEN", "GATE_PASSWORD")):
        os.environ.pop(name, None)
os.environ.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHON_DOTENV_DISABLED="true", MPLBACKEND="Agg")


def deny_network(event, args):
    if event in ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname", "socket.sendto"):
        raise RuntimeError("Offline RPC runner blocked network access")


sys.addaudithook(deny_network)
import pytest

selected = sys.argv[1:] or ["tests/test_rpc_user_agent.py"]
with tempfile.TemporaryDirectory(prefix="faultseeker-rpc-") as scratch:
    previous = Path.cwd()
    os.chdir(scratch)
    try:
        result = pytest.main(["-q", "-p", "no:cacheprovider", "--basetemp", str(Path(scratch) / "pytest"),
                              "--tb=line", *[str(ROOT / path) for path in selected]])
    finally:
        logging.shutdown()
        os.chdir(previous)
raise SystemExit(result)
