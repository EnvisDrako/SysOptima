# SysOptima Cortex

The Cortex is the Python reasoning layer for SysOptima. It receives events from the C++ sensor, enriches them with semantic tags, stores activity in SQLite, runs trust and response logic, and serves the active Flask dashboard.

Status: prototype. Some modules are implemented, some are partial, and several production features are still placeholders. Use the root `PRODUCTION_READINESS_ROADMAP.md` as the working completion checklist.

## Active Startup Path

Install dependencies:

```powershell
cd D:\SysOptima\Cortex
python -m pip install -r requirements.txt
```

Start the C++ sensor first from Visual Studio or from the built executable, then start Cortex:

```powershell
cd D:\SysOptima\Cortex\src
python launch.py
```

`launch.py` delegates to `main.py`, which starts the database, AI observer, graph, response orchestrator, named-pipe workers, and Flask dashboard.

The dashboard URL is printed during startup. By default it is:

```text
http://localhost:8050
```

## Important Files

- `main.py`: current application composition and worker startup.
- `protocol.py`: binary named-pipe event and command encoding.
- `flask_backend.py`: active REST/WebSocket dashboard backend.
- `database.py`: SQLite event storage.
- `trust_engine.py`: process trust scoring.
- `response_orchestrator.py`: staged monitor/suspend/kill decisions.
- `memory_scanner.py`: user-mode memory scan prototype.
- `quarantine_manager.py`: quarantine and restore logic.
- `malware_launcher.py`: experimental malware execution helper. Treat as unsafe until isolation placeholders are replaced.
- `dashboard_old.py`: legacy Dash dashboard, not part of the active startup path.
- `simple_listener.py`: legacy pipe listener, not part of the active startup path.

## Verification

Run the protocol unit tests without starting the C++ sensor:

```powershell
cd D:\SysOptima
python -m unittest discover -s Cortex\tests
```

Current broader module tests are in `src/test_modules.py`, but they touch Windows process and file-system behavior and should be run carefully.

## Current Known Gaps

- `main.py` is still too large and should be split into smaller modules.
- The IPC protocol has no version handshake yet.
- Threat-intel cache updates are not fully wired into the C++ sensor.
- Signature validation and signer extraction need production-grade implementation.
- The malware launcher network/filesystem isolation is placeholder-only.
- Legacy Dash documentation and code should either be archived or removed after the Flask path is fully verified.
