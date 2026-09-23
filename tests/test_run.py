import pytest
import json
import os

def test_trust_passport_generation():
    os.system("python3 run.py --export-dir ./audit_out")
    with open("./audit_out/trust_passport.json") as f:
        data = json.load(f)
        assert data["negative_state_assertions"]["authority_created"] is False
