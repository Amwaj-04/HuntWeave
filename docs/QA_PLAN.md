# HuntWeave — Release QA Plan

## Automated test coverage

**Current suite:** 23 test cases are included. The historical result of 18 passing tests on 2026-10-28 applies to an earlier revision and does not verify this release candidate. Run the complete current suite in a clean environment before marking this revision verified.
- Home route and three scenario cards
- Health endpoint and synthetic-data mode
- Scenario-specific event scoping
- Invalid source filter rejection
- Unknown scenario handling
- Finding save and persistence
- Per-scenario reset clears only the selected finding and notes
- Invalid verdict and malformed payload rejection
- Analyst note length limit
- JSON report structure and synthetic-data marker
- Case-insensitive event search
- Security response headers

## Manual checks required on a clean Windows machine
- [ ] Python 3.11+ installed and `START_HUNTWEAVE.bat` completes without errors.
- [ ] App opens at `http://127.0.0.1:5055`; server binds only to localhost.
- [ ] All three scenarios open and show the correct scoped events.
- [ ] Search works for event ID, account, host, message, and event type.
- [ ] Source filters work and empty results show a useful message.
- [ ] Every finding state saves, survives a restart, and appears in the exported JSON report.
- [ ] A 2,001-character note is rejected; a 2,000-character note is accepted.
- [ ] Unknown IDs return 404; invalid filters and malformed JSON return 400, not 500.
- [ ] Theme choice toggles and remains saved in the browser.
- [ ] Keyboard operation works: open, close with Escape, close button, focus behavior, and form labels.
- [ ] Desktop and narrow mobile widths remain usable; no horizontal overflow in core screens.
- [ ] No remote fonts, trackers, or external scripts are requested; the interface uses system font stacks.
- [ ] Git ignores the local SQLite database, `.venv`, `venv`, Python caches, and environment files.
- [ ] An older single-workspace `hunt_notes` table is preserved as `hunt_notes_legacy` during schema migration; the new per-browser workspace table is created successfully.
- [ ] Technique IDs and labels are reviewed against official MITRE ATT&CK references.
- [ ] Dependency versions and known advisories are checked before public release.
- [ ] Confirm `static/mark-light.svg`, `static/mark-dark.svg`, and `static/mark.svg` are the intended final assets and render correctly in both themes.

## Hosted demo checks (Render)
- [ ] Confirm HTTPS is active, Python 3.13.5 is selected, and `HUNTWEAVE_SECRET_KEY` is generated privately by the host.
- [ ] Confirm `/health` responds successfully after deployment.
- [ ] Confirm two separate browser profiles receive separate workspaces.
- [ ] Confirm saved notes may be lost after the free service spins down, restarts, or redeploys because no persistent disk is attached.
- [ ] Keep all input synthetic; do not enter real identities, IP addresses, or incident details.

## Important limitations
A passing automated suite does not prove the app is defect-free. Review the tests and execute the manual checklist. The hosted demo has no authenticated user accounts; browser workspaces are separated by signed session cookies, not verified identities. Security headers do not provide authentication, rate limiting, abuse protection, or production-grade hardening. Do not use the hosted demo for confidential information or operational security decisions.
