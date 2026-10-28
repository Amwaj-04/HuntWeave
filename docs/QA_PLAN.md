# HuntWeave — Release QA Plan

## Automated test coverage

**Latest recorded result (2026-10-28):** 18 tests passed on the author’s Windows environment. This records the reported test run; it does not replace the manual checks below.
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
- [ ] No remote fonts, trackers, or external scripts are required.
- [ ] Git ignores the local SQLite database, `.venv`, caches, and environment files.
- [ ] Technique IDs and labels are reviewed against official MITRE ATT&CK references.
- [ ] Dependency versions and known advisories are checked before public release.
- [ ] Confirm `static/mark-light.svg`, `static/mark-dark.svg`, and `static/mark.svg` are the intended final assets and render correctly in both themes.

## Important limitations
A passing automated suite does not prove the app is defect-free. Review the tests and execute the manual checklist. This application has no accounts or multi-user isolation and must remain local; security headers alone do not make a public deployment safe.
