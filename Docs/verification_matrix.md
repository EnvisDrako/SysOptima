# SysOptima Verification Matrix

Use this file to track what the prototype actually proves. A feature should not be described as complete unless it has a passing verification row here.

Status values:

- `Not Started`
- `Partial`
- `Manual Pass`
- `Automated Pass`
- `Blocked`

## Startup And Packaging

| Feature | Expected Behavior | Verification | Status | Notes |
| --- | --- | --- | --- | --- |
| Python dependency install | Active Cortex dependencies install from `Cortex/requirements.txt` | `python -m pip install -r Cortex\requirements.txt` | Not Started | Needs fresh environment check |
| Cortex launcher | `python launch.py` starts through the real Flask path without missing `dashboard.py` import | `cd Cortex\src; python launch.py` | Partial | Code path fixed; full runtime not yet tested here |
| C++ sensor build | Visual Studio builds `SysOptima_Sensor` with Krabs dependency available | Build in Visual Studio | Not Started | Keep Visual Studio workflow intact |
| Dashboard availability | Flask dashboard responds on configured port | Browser/API check for `http://localhost:8050` | Not Started | Requires runtime startup |

## IPC Protocol

| Feature | Expected Behavior | Verification | Status | Notes |
| --- | --- | --- | --- | --- |
| Binary event size | Python parser matches current C++ `BinaryEvent` layout | `python -m unittest discover -s Cortex\tests` | Automated Pass | Checks 1097-byte event |
| Binary command size | Python command packer matches current C++ `BinaryCommand` layout | `python -m unittest discover -s Cortex\tests` | Automated Pass | Checks 264-byte command |
| Event parsing | Fixed strings and numeric fields decode correctly | `test_protocol.py` | Automated Pass | Unit-level only |
| Command packing | Kill command packs type, PID, and param correctly | `test_protocol.py` | Automated Pass | Unit-level only |
| Protocol versioning | Incompatible Python/C++ protocol versions are rejected | TBD | Not Started | No version field yet |
| Command acknowledgement | Python can tell whether C++ action succeeded | TBD | Not Started | Needs protocol extension |

## Event Pipeline

| Feature | Expected Behavior | Verification | Status | Notes |
| --- | --- | --- | --- | --- |
| Process start event | Starting a test process appears in Cortex and dashboard | Manual test process launch | Not Started | Requires C++ sensor runtime |
| Process end event | Ending a test process is observed | Manual test process launch/exit | Not Started | Requires C++ sensor runtime |
| File write event | Controlled file write appears with path context | Manual file write test | Not Started | Requires sensor verification |
| Registry set event | Controlled registry write appears with key context | Manual registry test | Not Started | Use harmless test key |
| Network event | Test connection appears with destination context | Manual connection test | Not Started | Requires network monitor check |
| Memory alert | Forced scan finding flows into graph/API | Manual forced scan/API test | Partial | Scanner exists; event queue integration needs proof |

## Trust And Detection

| Feature | Expected Behavior | Verification | Status | Notes |
| --- | --- | --- | --- | --- |
| Trust score calculation | Known process info produces explainable score | Unit tests for `trust_engine.py` | Not Started | Needs tests |
| Real signer extraction | Publisher identity affects score | Signed file test | Not Started | Currently TODO/simplified |
| Real SHA-256 hash | Sensor hash matches external SHA-256 tool | Compare known file hash | Not Started | C++ function is simplified |
| Semantic tags | Known behaviors map to expected tags | Unit tests for semantic translator | Not Started | Needs extraction from `main.py` |
| Temporal patterns | Known event sequence raises expected pattern | Unit tests for temporal buffer | Not Started | Needs extraction from `main.py` |

## Response And Quarantine

| Feature | Expected Behavior | Verification | Status | Notes |
| --- | --- | --- | --- | --- |
| Decision policy | Threat/trust combinations choose expected action | Unit tests for response policy | Not Started | Current policy is embedded in orchestrator |
| Suspend command | Safe test process is suspended by C++ command | Manual test process | Not Started | Needs careful local test |
| Kill command | Safe test process is killed by C++ command | Manual test process | Not Started | Needs careful local test |
| Kill tree command | Safe parent/child process tree is killed | Manual test process tree | Not Started | Needs careful local test |
| Quarantine file | Test file is moved with metadata | `test_modules.py` or focused unit test | Partial | Existing test is broad/manual |
| Restore quarantine | Quarantined test file restores correctly | Focused quarantine test | Partial | Existing test is broad/manual |

## Dashboard And API

| Feature | Expected Behavior | Verification | Status | Notes |
| --- | --- | --- | --- | --- |
| Graph snapshot API | `/api/graph/snapshot` returns nodes/edges/stats | HTTP/API test | Not Started | Requires running Flask |
| Health/status API | Dashboard exposes sensor/database/queue health | `/api/health` HTTP/API test | Partial | Endpoint added; runtime test still needed |
| Pending reviews API | Pending actions visible to operator | HTTP/API test | Not Started | Requires response test |
| Quarantine API | Quarantine list/details/restore/delete available | HTTP/API test | Not Started | Requires sample data |
| Action result visibility | UI/API shows whether action succeeded | TBD | Not Started | Needs C++ acknowledgements |

## Threat Intelligence

| Feature | Expected Behavior | Verification | Status | Notes |
| --- | --- | --- | --- | --- |
| Feed download | Configured feed downloads and parses | Mocked/unit feed test | Not Started | Avoid network dependency in unit tests |
| Local feed cache | Hash/IP cache files are written with metadata | Focused unit test | Partial | Writes JSON workaround |
| Active C++ cache update | Python updates C++ threat cache without restart | TBD | Not Started | Protocol payload not implemented |
| Feed confidence | Match explains feed source and confidence | TBD | Not Started | Needs data model |

## AI

| Feature | Expected Behavior | Verification | Status | Notes |
| --- | --- | --- | --- | --- |
| Training mode | Samples are collected without enabling destructive actions | Manual/unit test | Not Started | Needs safer workflow |
| Model save/load | Trained model persists and reloads | Unit/integration test | Not Started | Requires sample fixture |
| Feature versioning | Old model schema is rejected or migrated | Unit test | Not Started | Not implemented |
| AI action boundary | AI cannot auto-kill alone in prototype mode | Policy test | Not Started | Needs explicit policy |

## Safety And Hardening

| Feature | Expected Behavior | Verification | Status | Notes |
| --- | --- | --- | --- | --- |
| Malware launcher guard | Unsafe launcher requires explicit opt-in | Config/unit test | Partial | Disabled by config, isolation still placeholder |
| Network isolation | Malware sample cannot reach external network | VM/sandbox test | Not Started | Placeholder only |
| Filesystem isolation | Malware sample cannot affect host files | VM/sandbox test | Not Started | Placeholder only |
| Dashboard binding | Dashboard is local-only by default or authenticated before remote exposure | Config/API check | Not Started | Current backend binds `0.0.0.0` |
| Audit trail | Detection, response, operator action, and config changes are logged | Database/API test | Not Started | Needs schema review |
