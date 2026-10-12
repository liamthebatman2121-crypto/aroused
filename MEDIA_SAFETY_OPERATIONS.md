# Media safety operations (pre-activation)

This document describes the local quarantine/escalation behavior and the approval gates still required. No suspicious media is automatically transmitted to a provider or law-enforcement/reporting service. No evidence-retention or reporting policy has been approved for this project.

## Current software behavior

- New album photo/video rows are stored with `album_media.state='processing'`; the pipeline begins `SCAN_PENDING`, and the processing job remains blocked while scanners are unconfigured.
- Existing media must not be treated as cleared merely because it predates the scanner interface. The startup migration leaves it `SCAN_PENDING`/`NOT_CONFIGURED` and publication stays blocked.
- All scan attempts are normalized to `clear`, `match`, `review_required`, or `unavailable`. The audit row stores provider/check identifiers, provider reference if supplied, start/completion timestamps, a safe error code, and an allow-listed metadata JSON object. Raw provider payloads and media bytes are not written to scan rows or logs.
- Missing, ambiguous, invalid, timed-out, or unavailable providers produce `unavailable` and remain private. Job retries are bounded. `match` and `review_required` create a restricted moderation case and security event; suspected CSAM hash matches are critical. No such result makes media public.
- Even all scanner checks returning `clear` leave the pipeline quarantined and `moderation_status='PENDING'`. Age assurance, creator consent/rights, human moderation approval, and canonical publication gates remain independent.
- Standard moderators do not see restricted case entries. Senior moderators and admins may see restricted queue metadata. The queue API does not return media bytes or a direct evidence URL.
- Direct media, upload, album, story, and feed reads continue to apply their authorization/publication checks. A detected match changes story/album out of public publication and denies byte routes, including to the owner while quarantined.

## Required response procedure before any scanner activation

1. Legal/operations must approve the jurisdictions covered, reporting duties, retention/legal hold, evidence access, deletion, appeals, and law-enforcement contact procedure.
2. Assign trained senior reviewers and backup/on-call coverage. Restrict accounts and access to the minimum staff; use MFA and audited admin access where available.
3. On a critical match, the system should quarantine immediately and open a restricted case. Staff must not download, screenshot, forward, or manually transmit suspected illegal content outside the approved evidence process. Do not add content to tickets, chat, email, source control, test fixtures, or logs.
4. A qualified reviewer follows the approved policy and applicable reporting requirements. The system currently records a local escalation marker only; CyberTipline submission or any other statutory reporting is not implemented and must not be inferred from an automated hash match.
5. Preserve evidence only under the approved retention/legal-hold policy. Current code does not copy objects to a separate evidence vault and does not define a retention period. Do not enable external submission until the provider’s submission rules and approval are confirmed.
6. Record only safe case decisions, provider/check IDs, timestamps, and normalized reason codes. Never place raw provider responses, secrets, media bytes, or unnecessary victim information in operational logs.

## Activation conditions

Before enabling any real scanner, confirm application eligibility and access approval for the service; review its exact data submission format, permitted use, data retention, geographic scope, match semantics, notification/reporting behavior, rate limits, and outage behavior; add credentials only through the deployment secret manager; run benign provider integration fixtures; verify network egress is denied by default for unconfigured adapters; and test timeout, invalid-response, duplicate, match, review, and failover paths. Do not use abusive media as a test fixture.
