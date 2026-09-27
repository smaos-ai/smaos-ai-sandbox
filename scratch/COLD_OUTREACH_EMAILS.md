# Outreach Variant 1: CISO / IT Risk Version

**Subject:** One question about autonomous-action evidence

Hi [First name],

I am researching a narrow operational-risk question for AI-enabled workflows: when an automated action times out after transmission, can the available records distinguish “not sent,” “sent but unconfirmed,” and “confirmed”?

I offer a short, observe-only review of one consequential workflow using a customer-supplied anonymized or redacted trace export. There is no production connector, runtime change, proxy deployment, credential access, or cloud upload required.

The review measures approval linkage, retry exposure, authority freshness, and evidence continuity after ambiguous outcomes.

Would a 15-minute conversation be useful to determine whether one workflow is suitable for this type of assessment?

Best,
Andrii Leukhin
Prague

---

# Outreach Variant 2: Platform / Engineering Version

**Subject:** What does your workflow record after a post-write timeout?

Hi [First name],

A narrow engineering question: if an automated workflow initiates a consequential API call, the request may have been transmitted, and the caller receives a timeout or disconnected response—what state does your workflow record?

Specifically, can it distinguish “not dispatched,” “dispatched but unconfirmed,” and “target-confirmed” without relying on the workflow’s own success message?

I run a small observe-only review against anonymized or redacted trace exports. It does not require credentials, runtime changes, a proxy, or production access. The output is an evidence-scoped report on approval linkage, retry exposure, authority freshness, and lifecycle evidence.

Would you be open to a 15-minute call to see whether one workflow is suitable?

Best,
Andrii Leukhin
Prague

---

# Post-Reply Response (When they ask for details)

Thanks, [First name].

The assessment is an observe-only review of one consequential workflow over an agreed evidence window. We work from an anonymized or redacted JSONL export and do not require credentials, network access, deployment changes, a proxy, or fault injection.

We assess four evidence questions:

1. Whether supplied records link approval/policy context to the resolved action.
2. Whether ambiguous post-dispatch outcomes have observed idempotency or reconciliation evidence.
3. Whether authority is observed to be current near the action-release point.
4. Whether the lifecycle can be reconstructed after a failure.

The output is a short evidence-scoped report with event-level findings, limitations, raw/normalized evidence hashes, and a prioritised remediation blueprint.

If useful, I can send the one-page scope before we schedule a call.
