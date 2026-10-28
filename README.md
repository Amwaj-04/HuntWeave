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
- Network access during the first setup to install Flask, unless the dependency is already cached

## Run on Windows

1. Extract the project folder to a normal writable location.
2. Double-click `START_HUNTWEAVE.bat`.
3. The script creates `.venv`, installs the requirements, starts the local server, and opens `http://127.0.0.1:5055`.
4. To run automated tests, double-click `CHECK_HUNTWEAVE.bat` after setup.

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

The database is created automatically at `data/huntweave.db`. It is ignored by Git because it can contain local analyst notes. You can use a different database path by setting the `HUNTWEAVE_DB` environment variable before starting the application. The application binds to `127.0.0.1` by default, not to every network interface.

The included scenarios are static teaching examples. They are not validated detections and their MITRE ATT&CK references are illustrative mappings. Confirm technique details against official references before using them in professional work.

## Architecture

- **Application:** Flask
- **Persistence:** SQLite via Python's standard library
- **UI:** HTML templates, CSS, and vanilla JavaScript
- **Tests:** Python `unittest` and Flask's test client

## Project boundaries

HuntWeave is not a production SIEM, EDR, SOAR, or threat-intelligence platform. It has no user accounts or multi-user isolation. Keep it local. Do not deploy it as a public service or expose it to a network without designing and independently reviewing authentication, authorization, CSRF protection, deployment configuration, data isolation, logging, and other production controls.

## QA status

The repository includes automated tests and a manual release checklist in `docs/QA_PLAN.md`. A release should only be called verified after running the tests in a clean environment and completing the manual checks. Passing syntax checks alone is not equivalent to a full application test.

## Brand status

HuntWeave is a working project name and the included light/dark SVGs are the selected visual identity for this portfolio release. This is not a claim of trademark clearance or exclusive name availability; perform a formal name and trademark review before commercial use.
