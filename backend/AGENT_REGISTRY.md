# Agent registry monitoring contract

Agent environments are `development`, `staging`, or `production`.
The agent detail endpoint exposes persisted-action metrics: `actions`,
`incidents` (blocked or approval-required checks), `blocked`, `approval_required`,
`allowed`, `prompt_injection_incidents`, `sensitive_data_incidents`,
`average_risk_score`, `pending_approvals` (pending and unexpired), and
`last_activity_timestamp` (most recent action check). Counts and averages are zero
with no actions; the last-activity timestamp is null. Counts describe check
attempts, including repeated checks, rather than distinct external operations.

The action feed includes `prompt_injection`, `sensitive_data`, and
`matched_policies` from check-time audit snapshots of original submitted
arguments. Detector previews and raw sensitive text are not stored in evidence.
Monitoring reads never re-run detectors on redacted arguments. Historical actions
without evidence return null detector findings and empty policy matches; their
detector incident counts are unknown and contribute zero recorded detections.
This is additive audit JSON and requires no destructive schema migration.

## Explicit legacy compatibility limitation

In local demo mode (`AGENTSHIELD_DEMO_MODE=true`, the local default), an entirely
empty registry permits unregistered legacy custom-action simulator requests.
This means unknown-agent enforcement is intentionally bypassed in that specific
compatibility state. The gateway still requires simulator mode and applies its
existing deterministic security policy. Creating any registry entry removes
this bypass. Shared mode (`AGENTSHIELD_DEMO_MODE=false`) always requires a
registered agent, even for an empty registry. A configured API key is enforced
for registry and gateway requests in either mode.
