# Chat monitor API

The chat monitor performs deterministic retrospective analysis of untrusted
transcripts. Pasted-text, metadata-only and fixed demos remain offline. The explicit
`chatgpt_share` mode can retrieve a public shared page with per-request consent;
it never reads cookies, uses ChatGPT credentials, runs JavaScript, invokes a tool,
or executes instructions in the transcript.

## Source type and access mode

The backend request field is **`source_type`**, with three supported values:

- `pasted_text`: create a session, optionally providing `pasted_text` for immediate
  analysis. Subsequent `/analyze` requests must provide the text to inspect.
- `metadata_only`: requires `url`, rejects `pasted_text`, and returns
  `not_evaluated` because no connector is configured. The URL is descriptive
  metadata, not evidence that its conversation was inspected.
- `chatgpt_share`: requires a canonical `https://chatgpt.com/share/<UUID>` URL,
  rejects `pasted_text`, and creates a session without fetching it. Each subsequent
  `/analyze` request must supply `{"fetch_consent": true}` and no pasted text.
  The full URL is retained for retrieval and returned in session responses.

`access_mode` is not an accepted field or alias. UI access-mode labels must be
mapped to the supported `source_type` values before calling this API. There is
no authenticated/private-link access mode. Unknown fields are rejected with HTTP 422.

## Endpoints

Base path: `/api/v1/chat-monitor/sessions`.

| Method | Path | Contract |
| --- | --- | --- |
| POST | Base | `{source_type, url?, pasted_text?, metadata?}` → session, HTTP 201 |
| GET | Base | `{sessions: [...]}` |
| GET | `/{id}` | Session with source type, URL (full only for `chatgpt_share`), metadata, status, timestamps |
| POST | `/{id}/analyze` | `{pasted_text?: string, fetch_consent?: boolean}` → analysis |
| GET | `/{id}/events` | `{events: [...]}` with redacted text and persisted analysis payload |
| GET | `/{id}/audit-events` | `{events: [...]}` with creation, analysis, limitation or failure receipts |

Session creation with text persists an analyzed event. Read that event for the
initial recommendation; session responses themselves contain session metadata,
not the latest analysis. Metadata-only creation records a limitation in audit
history and produces no transcript event.

## Analysis response

In addition to `session`, `status`, `limitation`, detector `findings`,
`redacted_preview`, sanitized `urls_detected`,
`tool_call_instructions_detected`, and `risk_score`, analysis returns:

- `decision`: `allow`, `redact`, `approval_required`, `block`, or `not_evaluated`.
- `policy_matches`: ordered, deterministic analysis policy IDs.
- `reasons`: corresponding explanations without copied sensitive input.
- `recommendation_scope`: always `retrospective_analysis`.
- `runtime_enforced`: always `false`.
- `executed`: always `false`.
- `source_trust_level`: always `untrusted`.
- `content_sha256`: SHA-256 of the exact UTF-8 supplied text before redaction;
  `null` for metadata-only analysis. Raw input is not retained. This fingerprint
  identifies input equality, not provenance, authentication, or safe content.

Transcript event and analysis audit payloads persist the decision, policy IDs,
reasons, recommendation scope, runtime-enforcement flag, and content fingerprint.
Metadata-only audit payloads persist `not_evaluated` and a null fingerprint.

## Recommendation policy

These recommendations describe how to treat imported text. **They are not
runtime action authorization or enforcement.** `allow` means no blocking
heuristic matched the submitted text, not proof that a conversation or action is
safe. `approval_required` recommends human review; it does not create an approval
request. Tool-call instructions are text indicators, not observed real tool calls.

| Policy ID | When matched |
| --- | --- |
| `chat_untrusted_imported_content` | Every supplied transcript |
| `chat_prompt_injection` | Existing prompt-injection detector matches |
| `chat_sensitive_data_redaction` | Existing sensitive-data detector matches |
| `chat_unsafe_links` | A textual HTTP(S) link is malformed or not publicly addressed |
| `chat_tool_instruction_review` | Possible tool-call instructions occur in text |
| `chat_elevated_risk_review` | Existing risk score is at least 60 |
| `chat_no_connector_configured` | Metadata-only analysis; no transcript inspected |

Decision precedence is deterministic: injection, unsafe links or risk >= 80 →
`block`; otherwise tool instructions or risk >= 60 → `approval_required`;
otherwise sensitive-data detection → `redact`; otherwise → `allow`.
Metadata-only always produces `not_evaluated`, empty findings and null risk.

## Input boundaries

For pasted-text and metadata-only, validated public HTTP(S) source URLs are accepted. Credentials, local and
non-public addresses and malformed URLs are rejected. Only the URL origin is
stored in these two offline modes; query, fragment and shared-link path are discarded. Transcript URL text
is masked in previews, including unsafe links. At most 100 unique sanitized
origins are returned; all textual links are still checked for unsafe-link policy.

Transcript size is limited to 128 KiB UTF-8 and request bodies to 256 KiB,
including streamed bodies. JSON schemas forbid unknown fields. Request validation
responses do not echo raw submitted text. Authentication uses
`X-AgentShield-API-Key` when an API key is configured; non-demo deployments fail
closed when no key is configured. Typical errors: 401 unauthorized, 404 unknown
session, 413 oversized input, 422 invalid input, 503 failed detector evaluation.
Detector failures produce no successful transcript event or recommendation.

## Public ChatGPT share import contract and limitations

Example (fake ID; not a working shared conversation):

```json
{"source_type":"chatgpt_share","url":"https://chatgpt.com/share/01234567-89ab-cdef-0123-456789abcdef"}
```

After creation, POST `/{id}/analyze` with `{"fetch_consent":true}`. Consent is
strictly boolean, defaults to false, is not stored, and is required again for every
import. Creating/listing/reading the session makes no network request. This mode
accepts **only** the exact lowercase HTTPS host/path with a lowercase hyphenated
UUID. Queries (even empty), fragments, credentials, ports (including 443), trailing
slashes, escaped paths, alternate hosts (including `chat.openai.com`) and private
`/c/` links are rejected. UUID syntax does not prove a share is publicly accessible.

The importer makes one unauthenticated GET: no cookies, authorization, environment
proxies, redirects, retries, browser session, or script execution. DNS results must
all be global unicast addresses; connections use a vetted literal IP with fixed
`chatgpt.com` Host and TLS SNI and certificate verification. The 15-second total
network deadline covers DNS and streaming; each network operation also has a
5-second timeout. Response bodies are capped at 2 MiB, extracted text at 128 KiB
UTF-8. Only UTF-8 HTML with identity content encoding is supported (compression is
requested off and refused to prevent unbounded decompression). There is no generic
URL-fetch endpoint.

Extraction accepts role-marked HTML (`data-message-author-role` or labeled
user/ChatGPT articles) and structured text messages in server JSON loader data,
including JSON-string `streamController.enqueue` payloads and bounded acyclic
Remix reference tables. Both user and assistant text must be present. Script text,
metadata, footer/navigation text and generic page text are not transcript evidence.
Only recognized JSON literals are parsed, never evaluated. Message text is analyzed
as untrusted through the same local detectors and redacted before persistence;
raw HTML and upstream exception/body details are neither persisted nor returned.
The retained share UUID is an intentional source locator; protect access to session
responses just as other session metadata.

This is best-effort server-rendered **text** import, not an authenticated ChatGPT
connector or a browser scraper. Client-only rendering, login/challenge pages,
removed shares, unsupported loader encodings, tool-only conversations, attachments,
images/audio, and conversations lacking both roles cannot be imported. JSON mapping
iteration follows the server's serialized order and may include visible branches;
it does not reconstruct a canonical active conversation branch. No transcript
completeness, provenance or account access is claimed.

Invalid URL/consent or absent/unsupported conversation yields 422; redirects,
upstream non-200 statuses (including 403/404), oversize responses, TLS/connection
failures or unsupported encodings yield 502; timeout or unsafe/unverifiable DNS
yields 503. There is no fallback fabricated success: failed imports set
`analysis_failed`, record a sanitized `chat_monitor_import_failed` audit receipt,
and create no new transcript event. Missing consent and invalid inputs fail before
retrieval. Existing successful events remain available after a later failed import.
Use pasted-text import when a share cannot be retrieved. Offline demos do not
invoke the importer. Tests use fake fixtures and mocked transports, never live shares.
