# HuntWeave — Product Specification

**Status:** Portfolio release; educational prototype, not a production security tool.

## Product intent
Teach a beginner-friendly, defensible threat-hunting workflow using synthetic data only.

## Primary user
A cybersecurity learner preparing to explain basic hypothesis-driven investigation in an entry-level SOC / security analyst interview.

## Core workflow
1. Read a scenario hypothesis, what to look for, and known limitations.
2. Inspect related synthetic events.
3. Search by event ID, account, host, message, event type, or source IP; optionally filter by source.
4. Compare chronology and contextual hints.
5. Record a supported, not-supported, or inconclusive finding with rationale and limitations.
6. Export a JSON report for review.
7. Optionally reset the selected scenario’s finding and notes without changing its event records or other scenarios.

## Scenarios
- **HW-001 — Authentication sequence:** failed sign-ins followed by success. The events warrant context review but do not establish compromise.
- **HW-002 — PowerShell parent context:** one process sequence is consistent with a synthetic deployment workflow; another includes a more unusual parent/command-line context. These indicators are leads, not proof of maliciousness.
- **HW-003 — Privileged role assignment:** records show that a role assignment occurred, but the dataset has no real change-management source to confirm authorization.

## Acceptance criteria
- Three scenarios can be opened independently.
- Every scenario states a hypothesis, a search target, limitations, and an illustrative ATT&CK reference.
- Search is case-insensitive and source filters are validated server-side.
- Unknown scenario IDs return 404; invalid filters and malformed review payloads return 400.
- Verdict values are allow-listed and analyst notes are limited to 2,000 characters.
- Findings persist locally and JSON reports include the current saved finding and scenario evidence.
- Reset affects only the selected scenario’s finding and notes; unknown scenario IDs return 404.
- A clean install creates its database automatically.
- Automated tests cover core routes, validation, search, and report output.
- The app binds to localhost by default and does not configure public hosting.

## Out of scope
Enterprise SIEM integration, real telemetry, endpoint actions, automated response, machine learning, user accounts, multi-user isolation, public hosting, and claims of formal compliance/certification.

## Name status
HuntWeave is a working title only. Initial web searches are not trademark clearance or proof of availability. Before public release, check official trademark databases, confusingly similar names, domain availability, and repository naming.
