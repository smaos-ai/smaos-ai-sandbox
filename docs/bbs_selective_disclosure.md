# BBS+ Redactable Trust Passports (Cross-Border A2A)

## 1. The Core Problem
When Agent A (Bank CZ) delegates execution to Agent B (Bank DE), the resulting Trust Passport contains a full audit trail. If Bank DE needs to provide this passport to a third-party risk auditor, it may violate GDPR if the passport exposes plaintext fields like `user_iban` or `transaction_amount`. 
Traditional Ed25519 signatures break if a single byte is altered or redacted.

## 2. The W3C BBS+ Solution
SMAOS integrates **BBS+ Signatures** (Data Integrity Cryptosuites) to enable **Selective Disclosure**.
The issuer signs the Trust Passport as a collection of independent statements (messages). The holder can later derive a zero-knowledge proof that reveals only a subset of the fields, while mathematically proving that the original issuer signed them.

## 3. Schema Design

### 3.1 Original Unredacted Passport (Internal)
```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "SmaosTrustPassport"],
  "credentialSubject": {
    "scenario_id": "prevent_unauthorized_handoff_escalation",
    "evaluated_disposition": "REFUSED",
    "user_iban": "CZ6508000000001234567890",
    "transaction_amount": 50000
  },
  "proof": {
    "type": "BbsBlsSignature2020",
    "proofValue": "..."
  }
}
```

### 3.2 Derived Redacted Passport (External Auditor)
The risk officer applies a JSON-LD frame to redact PII before transmission:
```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "SmaosTrustPassport"],
  "credentialSubject": {
    "scenario_id": "prevent_unauthorized_handoff_escalation",
    "evaluated_disposition": "REFUSED"
    // user_iban and transaction_amount are omitted
  },
  "proof": {
    "type": "BbsBlsSignatureProof2020",
    "proofValue": "..." // Derived ZK proof validating the remaining fields
  }
}
```

## 4. Auditor Verification
The offline WASM verifier reads the `BbsBlsSignatureProof2020`. It cryptographically confirms that the SMAOS engine signed the original document containing these exact visible fields, without ever learning the hidden values.
