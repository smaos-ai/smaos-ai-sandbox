import pytest
import json
import os
import subprocess
import sys

def test_trust_passport_generation(tmp_path):
    cmd = [sys.executable, "run.py", "--scenario", "504_timeout", "--export-dir", str(tmp_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0
    with open(tmp_path / "trust_passport.json") as f:
        data = json.load(f)
        assert data["negative_state_assertions_map"]["authority_created"] is False
        assert any("authority_created = false" in s for s in data["negative_state_assertions"])

