# SysOptima Production Readiness Roadmap

This file is the working checklist for turning SysOptima from an incomplete EDR prototype into either:

1. A complete, believable prototype suitable for demos, interviews, and research.
2. A longer-term production-grade Windows EDR foundation.

The current project has a strong architecture, but it mixes real implementation, old prototype files, presentation material, generated build artifacts, and placeholders. The first goal is not to add more features. The first goal is to make the project truthful, runnable, modular, and testable.

## Completion Levels

Use these levels to avoid confusing prototype completeness with production readiness.

### Level 1: Honest Runnable Prototype

The system has one documented startup path, the C++ sensor and Python Cortex communicate correctly, the dashboard loads, core events are visible, and all known placeholders are either implemented, disabled, or clearly marked as planned.

### Level 2: Complete Prototype

The system demonstrates the full intended workflow end to end: collect events, score trust, detect suspicious behavior, correlate events, show them in the dashboard, take staged response actions, quarantine files, and preserve evidence.

### Level 3: Production Candidate

The system is hardened enough for controlled real-world testing: reliable service lifecycle, defensive error handling, strong tests, safe defaults, signed binaries, least-privilege design, update handling, tamper resistance, and documented operational limits.

### Level 4: Production EDR

The system is ready for real endpoint deployment. This requires professional-grade reliability, security review, telemetry quality, update infrastructure, policy management, kernel visibility where required, incident response workflow, and long-term maintenance.

## Guiding Rules

- Make every module own one responsibility.
- Keep C++ responsible for fast Windows collection and reflex actions.
- Keep Python responsible for correlation, scoring, policy, storage, and UI.
- Keep IPC contracts versioned and documented.
- Do not claim production readiness until the system survives repeatable verification.
- Prefer explicit disabled states over fake implementations.
- Delete or isolate old prototype paths when they are no longer part of the product.

## Phase 0: Repository Truth And Hygiene

Goal: make the repo understandable before adding more code.

### 0.1 Create A Truthful Status Document

- Keep `README.md` as the public project summary.
- Add a short "Current Status" section that clearly says the project is an unfinished prototype.
- Remove or rewrite claims like "production ready", "feature complete", and "95% complete" unless they refer to a narrow verified module.
- Link this roadmap from the README.

Acceptance criteria:

- A new contributor can tell what works today, what is partial, and what is planned.
- No top-level document implies the system is production ready.

### 0.2 Clean Generated Files From Version Control Without Breaking Visual Studio

Current tracked/generated areas include Visual Studio `.vs` files, debug outputs, `.pdb`, `.ilk`, `.obj`, local build logs, NuGet package folders, and built binaries.

Tasks:

- Update `.gitignore` for Visual Studio, C++ build outputs, Python caches, local databases, model files, logs, quarantine folders, and sandbox folders.
- Keep actual Visual Studio project files, solution files, Krabs package references, source files, and filters needed for normal C++ development.
- Remove generated artifacts from Git tracking only after confirming they are not required to open or build the project in Visual Studio.
- Decide whether `sysoptima_events.db` is a sample artifact or local runtime state.
- If sample data is useful, move it to a clearly named `samples/` or `fixtures/` folder.

Acceptance criteria:

- `git status` shows only source/docs/config changes during normal development.
- Visual Studio still opens and builds the C++ sensor normally.
- Build outputs are reproducible and not treated as source.

### 0.3 Separate Active Code From Legacy Code

Current legacy/conflicting files:

- `Cortex/src/simple_listener.py`
- `Cortex/src/dashboard_old.py`
- `Cortex/src/launch.py`
- Old Dash instructions in `Cortex/README.md`

Tasks:

- Decide whether the active dashboard is Flask or Dash. Current active code points to Flask.
- Move legacy files to `legacy/` or delete them after confirming they are not needed.
- Rewrite startup docs around the active path.
- Remove references to missing `dashboard.py`.

Acceptance criteria:

- There is exactly one recommended way to run the prototype.
- No documented command imports missing modules.

## Phase 1: Make The Prototype Start Reliably

Goal: one command sequence starts the C++ sensor, Python Cortex, and web dashboard.

### 1.1 Fix Python Dependencies

Current issue: `flask_backend.py` imports Flask and Flask-SocketIO, but `Cortex/requirements.txt` still focuses on Dash.

Tasks:

- Add required runtime packages:
  - `flask`
  - `flask-socketio`
  - compatible SocketIO async backend, if needed
- Remove Dash/Plotly dependencies if Dash is no longer active.
- Split dependencies into required and optional sections.
- Add Windows-only notes for `pywin32`.

Acceptance criteria:

- `pip install -r Cortex/requirements.txt` installs everything needed for the active prototype.
- `python Cortex/src/main.py` does not fail because of missing Flask dependencies.

### 1.2 Fix The Launcher

Current issue: `launch.py` imports a missing `dashboard.py`.

Tasks:

- Refactor `launch.py` to call the real initialization path.
- Avoid duplicate startup logic between `launch.py` and `main.py`.
- Make the launcher print accurate prerequisites:
  - whether the C++ sensor must be started first
  - dashboard URL
  - required privilege level
  - config path

Acceptance criteria:

- `python Cortex/src/launch.py` either starts the full prototype or gives a precise, actionable error.
- No import points to missing files.

### 1.3 Define A Root Startup Flow

Tasks:

- Add a root-level `RUNBOOK.md` or a README section with exact commands.
- Include:
  - install dependencies
  - build sensor
  - run sensor
  - run Cortex
  - open dashboard
  - stop everything safely
- Document admin requirements.

Acceptance criteria:

- A developer on Windows can follow the instructions from a fresh clone.

## Phase 2: Stabilize The IPC Contract

Goal: C++ sensor and Python Cortex agree on event and command formats.

### 2.1 Create A Protocol Specification

Tasks:

- Create `Docs/ipc_protocol.md`.
- Document:
  - pipe names
  - event struct layout
  - command struct layout
  - field sizes
  - byte order
  - version number
  - event types
  - command types
  - error/reconnect behavior

Acceptance criteria:

- The C++ `BinaryEvent` and Python `struct.unpack` format can be checked against the spec.
- The command format is documented in one place.

### 2.2 Add Protocol Versioning

Tasks:

- Add a protocol version field to events and commands or define a startup handshake.
- Reject incompatible versions clearly.
- Log protocol mismatches with enough detail to debug.

Acceptance criteria:

- Python does not silently parse incompatible C++ events.
- C++ does not silently ignore incompatible Python commands.

### 2.3 Remove Old Pipe Listener Path

Current issue: `simple_listener.py` uses `\\.\pipe\SysOptimaPipe`, while active code uses `SysOptimaData` and `SysOptimaControl`.

Tasks:

- Delete, archive, or rewrite `simple_listener.py`.
- If kept as a diagnostic tool, update it to the current binary protocol.

Acceptance criteria:

- There is no stale IPC path in active source.

## Phase 3: Modularize The Cortex

Goal: make Python code easier to extend and test.

### 3.1 Split `main.py`

Current issue: `Cortex/src/main.py` is doing too much.

Proposed modules:

- `cortex/app.py`: application composition and lifecycle
- `cortex/protocol.py`: binary event and command encoding/decoding
- `cortex/events.py`: event models and normalization
- `cortex/semantic.py`: semantic tag generation
- `cortex/temporal.py`: temporal correlation
- `cortex/ai.py`: AI observer and model persistence
- `cortex/graph.py`: threat graph state and queries
- `cortex/pipes.py`: named pipe reader/writer
- `cortex/workers.py`: background worker threads
- `cortex/config.py`: config wrapper or existing config manager

Acceptance criteria:

- `main.py` becomes a small entry point.
- Core logic can be imported without starting threads or Flask.

### 3.2 Define Data Models

Tasks:

- Replace loose dict passing with dataclasses or typed models for:
  - raw sensor event
  - normalized event
  - process record
  - command
  - threat decision
  - quarantine record
  - pending review
- Add conversion helpers for API JSON output.

Acceptance criteria:

- Response orchestration, graph code, and Flask endpoints do not disagree on dict-vs-object process access.

### 3.3 Centralize Logging

Tasks:

- Replace scattered `print()` calls with a logging module.
- Use log levels.
- Add structured fields for PID, event type, action, confidence, and module.
- Keep console output readable for prototype mode.

Acceptance criteria:

- Logs can be redirected to a file without changing code.
- Debug output can be reduced in normal mode.

## Phase 4: Complete Core Detection Pipeline

Goal: make the main EDR workflow real end to end.

### 4.1 Process Event Collection

Tasks:

- Verify C++ ETW process start/end events are captured consistently.
- Include parent PID, image path, signer status, origin tag, and timestamp.
- Add event sequence IDs.
- Handle process reuse safely.

Acceptance criteria:

- Starting and stopping a known test process appears correctly in the dashboard and database.

### 4.2 File And Registry Events

Tasks:

- Verify file write and registry write ETW capture.
- Normalize paths.
- Suppress obvious noise safely.
- Preserve enough detail for forensic review.

Acceptance criteria:

- Controlled test actions generate expected events and semantic tags.

### 4.3 Network Events

Tasks:

- Verify network connection detection.
- Attach PID, destination IP, port, protocol, and process name.
- Avoid emitting duplicate noisy events.
- Integrate malicious IP checks.

Acceptance criteria:

- A test network connection appears with process attribution.

### 4.4 Memory Alerts

Tasks:

- Make memory scanner findings flow into the same event queue as sensor events.
- Include finding type, region metadata, trust score, and reason.
- Keep trusted JIT processes from flooding alerts.

Acceptance criteria:

- Forced memory scan can produce dashboard/API-visible findings.

## Phase 5: Trust Engine Completion

Goal: reduce false positives with real trust decisions.

### 5.1 Real Signature Validation

Current issue: signature handling is simplified.

Tasks:

- Use WinTrust or a reliable Windows API path to validate Authenticode signatures.
- Extract signer/publisher name.
- Distinguish:
  - unsigned
  - signed but invalid
  - signed by trusted publisher
  - signed by unknown publisher
  - revoked or expired where detectable

Acceptance criteria:

- Trust score changes based on real signer identity, not just a boolean.

### 5.2 Real File Hashing

Current issue: C++ hash function is marked simplified.

Tasks:

- Implement real SHA-256 in C++ using CryptoAPI, BCrypt, or another Windows-supported API.
- Use the same hash format across C++ and Python.
- Cache hashes safely.

Acceptance criteria:

- Known file hashes match external SHA-256 tools.

### 5.3 Trust Policy Model

Tasks:

- Move trust rules into a clearly versioned policy config.
- Support user whitelist/blacklist by hash and path.
- Record why trust score changed.
- Avoid trusting by path alone for high-risk actions.

Acceptance criteria:

- Every trust score can be explained in API/dashboard output.

## Phase 6: Response Orchestration Completion

Goal: safe, staged response that avoids reckless kills.

### 6.1 Define Decision Policy

Tasks:

- Document response levels:
  - observe
  - monitor
  - alert
  - suspend
  - kill
  - kill tree
  - quarantine
  - cleanup persistence
- Define thresholds by mode:
  - learning
  - smart
  - production
- Make trusted process handling explicit.

Acceptance criteria:

- A threat decision includes reason, score, trust context, and selected action.

### 6.2 Validate C++ Command Execution

Tasks:

- Test `CMD_KILL_PID`, `CMD_SUSPEND_PID`, and `CMD_KILL_TREE`.
- Add success/failure responses from C++ back to Python.
- Add timeout and retry behavior.

Acceptance criteria:

- Dashboard can show whether an action actually succeeded.

### 6.3 Quarantine Integration

Tasks:

- Ensure quarantine happens before destructive kill when file evidence is available.
- Preserve metadata:
  - original path
  - hash
  - PID
  - process name
  - threat reason
  - timestamp
  - action source
- Verify restore and permanent delete.

Acceptance criteria:

- A controlled test file can be quarantined, listed, restored, and deleted.

## Phase 7: Threat Intelligence Completion

Goal: threat feeds become functional, not decorative.

### 7.1 Python Feed Updater

Tasks:

- Implement feed download and parsing for selected feeds.
- Add feed source metadata and timestamps.
- Store feeds locally.
- Validate data before applying.
- Add rate-limit handling and retries.

Acceptance criteria:

- Feed update produces a local cache with known hashes/IPs and source metadata.

### 7.2 C++ Threat Cache Updates

Current issue: Python writes JSON as a workaround instead of updating C++ through the control protocol.

Tasks:

- Implement `CMD_UPDATE_THREAT_CACHE` or a dedicated cache reload command.
- Define payload format.
- Support atomic cache replacement.
- Log loaded counts and failures.

Acceptance criteria:

- Python can update the active C++ threat cache without restarting the sensor.

### 7.3 Feed Safety

Tasks:

- Avoid auto-killing solely because of untrusted community feed data unless confidence is high.
- Track feed source confidence.
- Support dry-run mode.

Acceptance criteria:

- Threat-intel matches explain source and confidence.

## Phase 8: Dashboard And Operator Workflow

Goal: make the UI useful for operating the prototype.

### 8.1 Dashboard Data Contract

Tasks:

- Define stable API response schemas.
- Keep API serialization separate from internal graph objects.
- Add health/status endpoint:
  - sensor connected
  - database ready
  - AI state
  - memory scanner state
  - queue sizes
  - last event time

Acceptance criteria:

- Dashboard can show degraded states instead of appearing broken.

### 8.2 Core Views

Required views:

- Live event stream
- Process graph
- Threat details
- Pending reviews
- Suspended processes
- Quarantine
- Configuration/mode
- System health

Acceptance criteria:

- Operator can inspect a threat and take action without using the console.

### 8.3 Action Safety

Tasks:

- Add confirmation for destructive actions.
- Show action results.
- Keep audit trail for operator-triggered actions.
- Add role/auth later if moving beyond local prototype.

Acceptance criteria:

- UI actions are visible in database/audit logs.

## Phase 9: AI And Baseline Learning

Goal: make AI useful without pretending it is magic.

### 9.1 Define AI Scope

Tasks:

- Document what AI is allowed to do:
  - recommend
  - raise score
  - flag anomaly
  - never auto-kill alone in prototype mode
- Keep deterministic rules as the primary response driver.

Acceptance criteria:

- AI output is explainable and not the only reason for destructive action.

### 9.2 Improve Feature Extraction

Tasks:

- Version feature vectors.
- Include behavioral rates, process ancestry, signature trust, path risk, event counts, and temporal patterns.
- Handle missing values consistently.

Acceptance criteria:

- Old models are rejected or migrated when feature schema changes.

### 9.3 Training Workflow

Tasks:

- Add explicit training mode.
- Store baseline metadata:
  - machine name
  - training period
  - sample count
  - feature version
  - model version
- Add export/import for models.

Acceptance criteria:

- AI can be trained, saved, loaded, and disabled safely.

## Phase 10: Malware Launcher And Sandbox Safety

Goal: prevent the malware launcher from being mistaken for a real sandbox until it is safe.

### 10.1 Rename Or Gate Unsafe Features

Current issue: network and filesystem isolation are placeholders.

Tasks:

- Either implement isolation or clearly label the launcher as unsafe local execution.
- Add config guard requiring explicit opt-in.
- Refuse to run samples unless safety preconditions are met.

Acceptance criteria:

- The prototype cannot accidentally present placeholder isolation as real containment.

### 10.2 Real Isolation Strategy

Options:

- Windows Sandbox integration
- Hyper-V VM snapshot workflow
- Dedicated sacrificial VM
- Restricted user plus firewall rules for prototype only

Tasks:

- Choose one isolation strategy.
- Implement launch, monitor, collect, revert/cleanup.
- Block external network by default.

Acceptance criteria:

- Running a sample does not expose the host system beyond the documented risk model.

## Phase 11: Database And Forensics

Goal: make stored evidence useful and durable.

### 11.1 Schema Review

Tasks:

- Version the SQLite schema.
- Add migrations.
- Ensure indexes for PID, timestamp, event type, threat score, hash, and action.
- Store raw event and normalized event separately if useful.

Acceptance criteria:

- Database can survive schema changes without manual deletion.

### 11.2 Audit Trail

Tasks:

- Log:
  - detection decisions
  - response actions
  - operator actions
  - config changes
  - quarantine actions
  - feed updates
- Include success/failure and reason.

Acceptance criteria:

- For a detected process, the system can explain what happened and why.

## Phase 12: Testing And Verification

Goal: make progress measurable.

### 12.1 Unit Tests

Targets:

- Protocol pack/unpack
- Semantic translator
- Temporal correlation
- Trust score calculation
- Config manager
- Quarantine metadata
- Threat-intel parsing
- Response decision policy

Acceptance criteria:

- Tests can run without starting the C++ sensor.

### 12.2 Integration Tests

Targets:

- Python startup without sensor
- Python reconnect after sensor starts
- C++ sensor emits process event
- Python receives and stores event
- Dashboard API returns event
- Command queue sends suspend/kill command to test process

Acceptance criteria:

- A scripted smoke test verifies the end-to-end prototype.

### 12.3 Manual Verification Matrix

Create `Docs/verification_matrix.md` with rows for:

- feature
- expected behavior
- command/test
- result
- status
- notes

Acceptance criteria:

- Every claimed feature has a verification row.

## Phase 13: Windows Service And Deployment

Goal: move from developer-run scripts to a managed endpoint component.

### 13.1 Sensor Service

Tasks:

- Run C++ sensor as a Windows service.
- Handle start/stop/restart cleanly.
- Log to Windows Event Log or structured log files.
- Define required privileges.

Acceptance criteria:

- Sensor starts on boot and can be controlled through Service Control Manager.

### 13.2 Cortex Service Or Agent

Tasks:

- Decide whether Cortex is a service, local app, or operator console.
- If service, use Windows service wrapper or native service implementation.
- Separate dashboard from backend if needed.

Acceptance criteria:

- The system can run without an interactive terminal.

### 13.3 Packaging

Tasks:

- Produce repeatable build artifacts.
- Add versioning.
- Include config templates.
- Include uninstall/cleanup procedure.

Acceptance criteria:

- A clean machine can install and remove the prototype predictably.

## Phase 14: Security Hardening

Goal: make the EDR itself harder to abuse or break.

### 14.1 Privilege Boundaries

Tasks:

- Minimize admin/SYSTEM usage.
- Separate UI privileges from sensor privileges.
- Validate all commands crossing IPC.
- Prevent arbitrary path actions from the dashboard.

Acceptance criteria:

- A compromised dashboard cannot trivially execute arbitrary privileged actions.

### 14.2 Tamper Resistance

Tasks:

- Protect config files.
- Protect quarantine folder.
- Protect service process where possible.
- Detect sensor shutdown.
- Add heartbeat between components.

Acceptance criteria:

- Basic tamper attempts are visible and logged.

### 14.3 Secure Defaults

Tasks:

- Disable malware launcher by default.
- Disable destructive auto-kill in learning/demo mode.
- Require explicit config for threat-intel auto-updates.
- Bind dashboard to localhost by default.
- Add authentication before remote dashboard access.

Acceptance criteria:

- Default run mode is safe for development.

## Phase 15: Kernel Visibility Roadmap

Goal: decide whether a kernel driver is actually needed.

This is not required for a complete prototype, but it is likely required for a serious production EDR.

Potential driver responsibilities:

- Process creation callbacks
- Image load callbacks
- Registry callbacks
- File minifilter events
- Handle access monitoring
- Process injection signals
- Tamper resistance support

Tasks:

- Create a separate driver design document.
- Define what user-mode ETW cannot see reliably.
- Decide minimum viable kernel features.
- Keep driver code in a separate module/project.

Acceptance criteria:

- Kernel work is treated as a separate milestone, not implied by current code.

## Recommended Work Order

Start here:

1. Phase 0: repository truth and hygiene.
2. Phase 1: reliable startup and correct dependencies.
3. Phase 2: IPC protocol specification and cleanup.
4. Phase 3: modularize Cortex enough to test it.
5. Phase 12: add protocol/unit tests early.
6. Phase 4: complete the core event pipeline.
7. Phase 5: finish trust engine basics.
8. Phase 6: make response actions verifiable.
9. Phase 8: make dashboard operator workflow real.
10. Phase 7: complete threat-intel sync.
11. Phase 11: improve database/audit evidence.
12. Phase 10: fix or disable malware launcher safety claims.
13. Phase 13: service/deployment.
14. Phase 14: hardening.
15. Phase 15: kernel driver roadmap.

## First Implementation Sprint

This is the best first sprint because it creates a stable base for every later task.

### Sprint 1 Goals

- Fix `requirements.txt` for the active Flask backend.
- Fix or replace `launch.py`.
- Create `Docs/ipc_protocol.md`.
- Archive or update `simple_listener.py`.
- Update README to link this roadmap.
- Add `.gitignore` entries for generated files.
- Remove generated artifacts from Git tracking only after confirming Visual Studio/Krabs still opens and builds cleanly.
- Add a minimal smoke test for protocol event parsing.

### Sprint 1 Done Means

- Fresh dependency install works.
- The active Python app starts.
- The missing dashboard import is gone.
- The IPC struct is documented.
- The repo status is clean after build/run.
- The project no longer overclaims its current maturity.

## Definition Of Complete Prototype

SysOptima can be called a complete prototype when all of these are true:

- C++ sensor builds from source.
- Python Cortex starts from documented commands.
- Sensor and Cortex connect over named pipes.
- Process, file, registry, network, and memory events reach Python.
- Events are stored in SQLite.
- Dashboard shows live system health and events.
- Trust score is explainable.
- Response decisions are explainable.
- At least suspend, kill, kill tree, and quarantine are tested against safe test processes/files.
- Threat-intel can update active detection data or is explicitly disabled.
- AI can be trained/loaded or is explicitly optional.
- All placeholders are either implemented, disabled, or listed as future work.
- A verification matrix proves the claims.

## Definition Of Production Ready

SysOptima should not be called production ready until all of these are true:

- Runs as managed Windows services.
- Has reliable install/update/uninstall.
- Has signed binaries.
- Uses real cryptographic hashing and signature validation.
- Has tested IPC versioning and failure handling.
- Has security-reviewed dashboard/API controls.
- Has safe defaults and authentication for any non-local UI.
- Has robust logging and audit trails.
- Has automated unit and integration tests.
- Has documented performance limits.
- Has tamper detection and recovery behavior.
- Has a clear policy model for detection and response.
- Has been tested on clean Windows systems and realistic workloads.
- Has a documented false-positive handling workflow.

## Current Highest-Risk Gaps

- Missing/incorrect dashboard startup path.
- Flask dependencies missing from requirements.
- Trust scoring depends on simplified signature/signer handling.
- C++ hash function is simplified.
- Threat-intel update path is not wired into the active C++ cache.
- Malware launcher isolation is placeholder-only.
- Old docs overstate implementation completeness.
- Generated Visual Studio/build artifacts are tracked.
- No verification matrix proving feature claims.

## Notes For Future Work

When implementing this roadmap, prefer small vertical slices:

- One protocol test before refactoring all IPC.
- One verified dashboard API before rebuilding UI.
- One real trust signal before adding more scoring rules.
- One safe response action before expanding auto-response.
- One feed integrated end to end before adding more feeds.

The project will improve faster by making existing claims true than by adding new unverified features.
