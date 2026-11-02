# HuntWeave

**From hypothesis to evidence.**

HuntWeave is a local-first, educational threat-hunting lab. It helps a learner practice a small, defensible investigation workflow: state a hypothesis, inspect synthetic events, weigh context, record a conclusion, and export a report.

> **Training only.** All included records are synthetic. HuntWeave does not collect endpoint telemetry, run commands on endpoints, connect to a SIEM, or prove that a real environment is compromised. Do not use its findings for operational security decisions.

## What is included

- Three guided investigations covering authentication patterns, PowerShell parent-process context, and privileged role assignment.
- A searchable event explorer scoped to the selected investigation.
- Case-insensitive event search and source filtering.
- Four finding states: `NOT_REVIEWED`, `SUPPORTED`, `NOT_SUPPORTED`, and `INCONCLUSIVE`.
- Local SQLite persistence for analyst notes and findings.
- A per-scenario **Reset finding** action that clears only that scenario’s saved conclusion and notes; the synthetic event dataset is preserved.
- JSON report export with the hypothesis, limits, conclusion, and related evidence.
- Light/dark themes, responsive layout, and the selected custom light/dark logo marks.
- Windows start and test scripts plus automated tests.

## Requirements

- Python 3.11 or newer
- `pip`
- Network access during the first setup to install Flask and Gunicorn, unless the dependencies are already cached

## Run on Windows

1. Extract the project folder to a normal writable location.
2. Double-click `START_HUNTWEAVE.bat`.
3. The script creates `.venv`, installs the requirements, starts the local server, and opens `http://127.0.0.1:5055`.
4. To run automated tests, double-click `CHECK_HUNTWEAVE.bat`; it creates `.venv` if needed, installs the requirements, and runs the test suite.

If the browser opens before the server is ready, wait a moment and refresh. To stop the server, close the console window titled **HuntWeave server**.

## Run manually

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m unittest discover -s tests -v
.venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5055`.

## Data and privacy

The database directory and `data/huntweave.db` are created automatically on first startup, and the 18 synthetic events are seeded when the events table is empty. The database is ignored by Git because it can contain analyst notes. You can use a different database path by setting the `HUNTWEAVE_DB` environment variable before starting the application. The local development server binds to `127.0.0.1` by default. If an older single-workspace database is detected, its previous `hunt_notes` table is preserved as `hunt_notes_legacy` before the new per-browser schema is created; the archived findings are retained for reference but are not automatically imported into browser workspaces.

### Public demo deployment

The repository includes a `render.yaml` Blueprint for a hosted educational demo. It pins the Render runtime to Python 3.13.5, uses the free web-service plan, and generates a private session secret. Each browser receives a separate workspace for verdicts and analyst notes using a signed session cookie; the event records remain synthetic and read-only. Set a strong, private `HUNTWEAVE_SECRET_KEY` in the hosting environment. Do not reuse the local development fallback secret in a public deployment. The hosted demo is for portfolio evaluation only, not sensitive notes or operational security decisions. On Render’s free plan, the service can spin down after 15 minutes without traffic and takes about a minute to wake on the next request. Its filesystem is ephemeral, so saved workspace notes may be lost after spin-down, restart, or redeploy. The 18 synthetic events are recreated automatically when the database is initialized. Do not enter real account names, IP addresses, incident details, or other confidential information.

The included scenarios are static teaching examples. They are not validated detections and their MITRE ATT&CK references are illustrative mappings. Confirm technique details against official references before using them in professional work.

## Architecture

- **Application:** Flask
- **Persistence:** SQLite via Python's standard library
- **UI:** HTML templates, CSS with system font fallbacks, and vanilla JavaScript
- **Tests:** Python `unittest` and Flask's test client

## Project boundaries

HuntWeave is not a production SIEM, EDR, SOAR, or threat-intelligence platform. It has no user accounts and the per-browser workspace is not an authenticated identity or a place for confidential information. The public demo is limited to synthetic events and portfolio evaluation. It is not designed for operational use or sensitive data. A production service would require independent security review and additional controls, including authentication, authorization, abuse protection, monitoring, and deployment hardening.

## QA status

The repository includes automated tests and separate local/hosted-demo checklists in `docs/QA_PLAN.md`. A release should only be called verified after running the full current test suite in a clean environment and completing the relevant manual checks. Passing syntax checks alone is not equivalent to a full application test.

## Brand status

HuntWeave is a working project name and the included light/dark SVGs are the selected visual identity for this portfolio release. This is not a claim of trademark clearance or exclusive name availability; perform a formal name and trademark review before commercial use.
