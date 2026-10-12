# Production launch blocker checklist

Audit date: 2026-10-10. This is a code/test/documentation audit, not a launch approval. The app remains on SQLite. No real provider is configured or called, and no original media or production data was changed.

Priority meaning: **P0** blocks safe public launch or creator publication; **P1** required before a reliable production deployment; **P2** important operational hardening. Marked complete means code/tests exist locally, not that a service is operational.

## 1. Can implement locally

| Priority | Item | Current verified state | Next local work |
|---|---|---|---|
| P0 | Publication and media access gates | Implemented fail-closed `canPublishAlbum()` and direct API allow/deny coverage for private, unpublished, unlisted, quarantined, rejected, scheduled, owner, and cross-account access. | Preserve these invariants as providers are added; no UI state is a control. |
| P0 | Safe upload request bounds and format checks | Request cap now rejects over-limit `Content-Length` before buffering and retains a max-byte check for streaming/chunked bodies. Tests cover oversized bodies, unsupported MIME, extension mismatch, invalid signatures, no DB rows on rejection, and no unauthenticated upload. | P1 follow-up: streaming multipart ingestion, global concurrency/byte budget, request timeout, parser isolation, actual container/image decode, pixel/frame limits. The current multipart parser still buffers request bodies in memory. |
| P0 | Moderation report consistency | Report, moderation case, critical security event, and urgent quarantine/status changes now run in one SQLite transaction. Regression test forces case insertion failure and verifies no orphan report or partial state changes; success test verifies critical case and denied media bytes. | Add durable operator alert delivery and idempotency/duplicate-report handling only after product policy is decided. |
| P0 | Moderator/admin/comment authorization | Existing direct tests cover moderator vs senior moderator vs admin. Added post-specific comment review, disabled-comments denial, moderator removal denial, and admin comment-removal coverage. | Continue route-by-route allow/deny tests for new moderator actions. |
| P1 | Security/auth/session and publication regressions | Direct API suite covers login enumeration parity, logout/revocation, reset token expiry/replay, same-origin checks, rate limits, roles, IDOR, and publication bypass attempts. | Add browser/proxy deployment contract tests once a deployment platform and proxy behavior are selected. |
| P1 | Production configuration | Startup validator rejects missing production essentials and local storage; shape-check command prints no secrets. | Extend with platform-specific checks after deployment target and proxy trust boundary are selected. |
| P1 | Operational visibility | Safe structured logging plus liveness/readiness endpoints exist. | Add metrics, alert routing, log retention/aggregation, rate-limit cleanup, expired session/token cleanup, and database/storage growth alarms. |
| P1 | Backup/restore | One historic SQLite+uploads backup and separate restore copy have been reverified. | Implement automated consistent SQLite+object metadata backups only after deciding deployment filesystem, media snapshot consistency, retention, encryption, and recovery objectives. The current script verifies one existing artifact; it does not create ongoing backups. |
| P1 | Background processing | Local worker mechanics provide claims, leases, retry/backoff, terminal failures, sanitized errors, and tests. It is intentionally not started without a processor and does not clear safety gates. | Add an isolated worker process only after defining processor contract, sandbox limits, temp-file cleanup, and durable failure/alert behavior. |
| P2 | Schema lifecycle and resilience | SQLite runtime preserved; staging PostgreSQL schema/import previously passed its checks. | Add versioned SQLite migrations, retention jobs, concurrency/load tests, and recovery/rollback tests. PostgreSQL remains staging-only. |

## 2. Requires an external provider/account

These are candidates to evaluate, not selections or claims of readiness. Confirm availability, adult-content terms, data residency, retention, legal basis, pricing, and vendor security with the provider before account creation or credentials. No provider has been purchased or configured.

| Priority | Capability | Candidate(s) for evaluation | Integration and proof required |
|---|---|---|---|
| P0 | Email verification/recovery | Resend is already implemented in code but unconfigured. | Verify sender domain, secret-manager storage, real delivery, bounce/failure behavior, rate limiting, and reset flow. |
| P0 | Age assurance | Yoti Age Verification API is one candidate; jurisdiction and method must be reviewed before selection. Its developer docs describe API-key bearer authentication and session creation. | Server-side signed/verified callbacks or polling, state/replay protection, minimal retention, revocation/expiry, test credentials, and real integration tests. Email OTP/self-attestation cannot set provider-verified age. |
| P0 | Known illegal-content matching | Microsoft PhotoDNA Cloud Service is a candidate subject to qualification, approval, and intended-use terms. | Access approval, licensed/qualified integration, exact handling/escalation/legal process, vetted fixtures, provider outage behavior, and restricted evidence handling. Never substitute a generic perceptual hash. |
| P0 | Image/video content moderation | Amazon Rekognition Content Moderation is a candidate for triage, including asynchronous video analysis; it is not a legal age check or a complete CSAM/consent verifier. | Determine AWS policy eligibility for this product/content, regions and data handling; implement async callbacks/polling, timeouts, versioned verdicts, human review, and real provider tests. It must not be treated as a standalone safety guarantee. |
| P0 | Malware scanning | ClamAV is a self-hosted candidate engine, not a hosted provider or a guarantee that media is safe. Official docs require signature databases and describe `clamscan`/`clamd`. | Securely deploy and patch the scanner, update signatures, isolate scanning, enforce time/memory limits, verify fail-closed behavior, and test clean/malicious vendor-approved samples. |
| P0 | Media decoding/transcoding | A pinned FFmpeg build and/or a maintained image decoder can be evaluated; this is a software supply-chain choice rather than a turnkey safety provider. | Isolate untrusted parsers, cap CPU/memory/disk/time, validate decoded streams and dimensions, strip metadata, hash outputs, and test malformed/oversized media. No decoder is currently configured. |
| P1 | OAuth | Google, Reddit, or X developer accounts depending on product decision. | Register redirect URIs, choose scopes, implement state/PKCE/issuer/audience validation, secure identity linking, and provider-specific integration tests. Current schema alone is not OAuth. |
| P1 | Private object storage | AWS S3 or another compatible private object service. The S3 adapter exists. | Create account/bucket only after approval; enforce public access blocks, owner-enforced ACLs, encryption, least-privilege role, lifecycle/versioning as decided, and real authorization/integration tests before any media copy. |
| P1 | Operational email/alerts | A chosen alerting/on-call service. | Human owner, escalation paths, delivery tests, privacy-safe payloads, and actionable alert thresholds. |

## 3. Requires an operational decision or human staff

| Priority | Decision/staffing item | Required decision/evidence |
|---|---|---|
| P0 | Launch jurisdictions and legal obligations | Counsel identifies launch regions, age-assurance requirements, records/notice/retention, copyright/takedown obligations, privacy obligations, and prohibited content. Do not choose an age provider or retention policy before this. |
| P0 | Consent and rights verification | Define what evidence is required for each depicted person, identity/age verification, release/withdrawal, per-media binding, revocation, dispute, and takedown. Current declarations are attestations and are not evidence verification. Counsel/operations must approve the workflow. |
| P0 | Human moderation coverage | Name trained staff, coverage hours, urgent suspected-minor/non-consensual escalation SLAs, evidence access restrictions, audit process, appeals, leave/backup coverage, and incident response. Software queue alone is not staffed moderation. |
| P0 | Safety provider dispositions | Define which outcomes block, quarantine, escalate, or allow, who can resolve a case, appeals/false positive handling, and provider outage policy. No automatic clear on timeout or uncertain result. |
| P1 | Data retention and deletion | Approve retention/legal-hold rules for reports, verification references, moderation evidence, logs, backups, sessions, and deleted accounts; define deletion verification and restricted access. |
| P1 | Deployment and proxy boundary | Select host/region, TLS termination, trusted proxy behavior, bind address, storage persistence, secret manager, firewall, rate-limit boundary, and deployment/rollback method. Do not expose publicly before review and approval. |
| P1 | Backup objectives | Choose RPO/RTO, retention, encryption/key custody, who can restore, periodic restore cadence, and whether an upload freeze/consistent snapshot is required. |
| P1 | Security incident ownership | Assign a technical on-call, vendor escalation contacts, credential rotation/revocation process, breach triage and reporting timelines, and audit-log review owner. |

## External candidate source notes

- [Yoti Age Verification API](https://developers.yoti.com/age-verification-api) describes the API and its bearer-token model; product/legal suitability is not established by these docs.
- [Amazon Rekognition content moderation](https://docs.aws.amazon.com/rekognition/latest/dg/moderation.html) describes image and stored-video moderation. It is a triage signal, not a substitute for age assurance, consent evidence, or human decisions.
- [Microsoft PhotoDNA FAQ](https://www.microsoft.com/en-us/photodna/faq) describes service-purpose and usage controls; access is not assumed.
- [ClamAV documentation](https://docs.clamav.net/manual/Usage/Scanning.html) describes scanning and signature database use; a clean antivirus result is not a content-safety verdict.
