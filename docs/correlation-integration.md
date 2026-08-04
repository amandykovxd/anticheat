# Audit-Only Correlation Service

The reference receiver retains every verified event, including event names it
does not recognize. Correlation runs only after the event-chain and remote
anchor checks succeed. Client binaries receive no decision or account action.

## Rule format

Install a rule with authenticated `POST /v1/rules`:

```json
{
  "rule_id": "kernel-memory-correlation",
  "version": 1,
  "required_events": [
    "kernel_thread_start_unlinked",
    "executable_private_region"
  ],
  "window_events": 4096,
  "outcome": "suspicious_session",
  "require_attestation": true,
  "min_samples": 100,
  "max_false_positive_rate": 0.01
}
```

Rule versions are immutable and monotonically increasing. Every newly
installed version starts in `audit_only`, even when an earlier version was
active. A decision stores the exact `session_id:event_seq` inputs, rule ID,
rule version, outcome, and rollout mode.

## Measurement and promotion

Submit reviewed decision feedback to
`POST /v1/decisions/<decision-id>/feedback` with
`{"false_positive":false}`. `POST /v1/rules/<rule-id>/promote` succeeds only
after the configured sample count is reached and the reviewed false-positive
rate is within the rule threshold. Promotion changes server-side decision
classification only; it does not send enforcement instructions to clients.

Read current metrics through `GET /v1/rules/<rule-id>` and session decisions
through `GET /v1/sessions/<session-id>/decisions`.

## Rollback and audit

`POST /v1/rules/<rule-id>/rollback` with `{"version":1}` changes the current
version pointer without deleting later versions, decisions, feedback, or raw
events. Install, promotion, feedback, and rollback operations are retained in
`correlation_rule_audit`.

The SQLite implementation is a reference service. Production deployments must
place administrative routes behind a dedicated authorization policy and
replicate rule, decision, feedback, and audit tables to append-only storage.
