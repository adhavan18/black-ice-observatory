import subprocess
import sys
import time
from urllib.request import urlopen

def test_local_authorized_target_health_contract():
    process = subprocess.Popen([sys.executable, "labs/authorized_target.py"])
    try:
        time.sleep(0.15)
        with urlopen("http://127.0.0.1:8765/health") as response:
            assert response.status == 200
            assert b"ok" in response.read()
    finally:
        process.terminate(); process.wait(timeout=2)
