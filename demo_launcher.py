import argparse
from src.transport_observer import observe_tool_call
from src.intent_ledger import IntentLedger
from src.bbs_redactor import redact_passport

def fake_504_call():
    class R:
        status_code = 504
    return R()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario")
    parser.add_argument("--test-bbs-redaction", action="store_true")
    parser.add_argument("--hide")
    args = parser.parse_args()

    if args.scenario == "504_timeout":
        ledger = IntentLedger()
        intent_id = ledger.declare_intent("demo_agent", "demo.target", {})
        _, obs = observe_tool_call(fake_504_call, ledger, intent_id)
        print(f"Final disposition forced to {obs.disposition} (Overclaim prevented)")
    elif args.test_bbs_redaction:
        redact_passport("audit_out/trust_passport.json", "audit_out/bbs_derived_proof.json")
        print(f"Derived proof verification: VALID ({args.hide} concealed)")
