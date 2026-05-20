# SysOptima EDR

This repository is an unfinished Windows EDR prototype. The project intent is clear: build a multi-layer endpoint detection and response system where a native Windows sensor does fast collection and reflex actions, and a Python "Cortex" layer does richer reasoning, correlation, AI-based anomaly detection, quarantine, and operator-facing UI.

The repo is not production-ready. Several files describe it as "complete", "95% complete", or "production ready", but the implementation still contains placeholders, partial integrations, missing modules, and mismatches between docs and code.

For the ordered implementation checklist, see `PRODUCTION_READINESS_ROADMAP.md`. For the current prototype startup flow, see `RUNBOOK.md`.

## What You Appear To Be Building

From the planning docs and notes, the intended product is:

- A Windows-first EDR with a multi-brain architecture.
- A native sensor for fast event capture, trust checks, memory scanning, process-tree actions, and local threat cache.
- A Python reasoning layer for semantic tagging, temporal correlation, graph analysis, trust-aware response, AI anomaly detection, database logging, and web/API access.
- A future kernel driver layer for deeper visibility into hollowing, APC injection, syscall abuse, and fileless techniques.
- A practical operator workflow: observe process behavior, correlate attack patterns, contain aggressively only when confidence is high, and avoid false positives through trust scoring and staged response.

## Current Repo Status

High-level status as of this snapshot:

- `Cortex/` contains the main prototype logic and is the most developed part of the repo.
- `SysOptima_Sensor/` contains a Visual Studio C++ sensor prototype with real code plus some unfinished threat-intel pieces.
- `Docs/` contains the strongest statement of intent. These documents are architecture and roadmap material, not a reliable statement of what is already implemented.
- There is no kernel driver in this repo even though the architecture documents treat it as Brain 0 / Layer 0.
- The active web/dashboard path is now the Flask backend and static UI. Some older docs/code still refer to Dash and should be treated as legacy until removed.
- The repository includes generated binaries and debug artifacts under `SysOptima_Sensor/.../x64/Debug`, which indicates the sensor has been built locally at least once.

Practical maturity:

- Architecture vision: strong
- Prototype code volume: substantial
- Integration completeness: partial
- Production readiness: not there yet

## Repo Structure

- `Docs/Complete Architecture`
  The full target architecture, including kernel driver, sensor, IPC, Python cortex, UI, AI, reporting, and roadmap.
- `Docs/file structure.md`
  Earlier architecture and module decomposition for the "3-brain" design.
- `Great questions.docx`
  Design discussion notes. This is useful because it explains why certain choices were made: reducing graph UI friction, training AI safely, avoiding false positives, and moving toward staged response instead of instant kills.
- `SysOptima_Interview_Guide.html`
  A polished explanation of the intended architecture for presentation/interview use. It describes the target system better than the implemented system.
- `Cortex/`
  Python side: graphing, threat reasoning, configuration, DB, response orchestration, quarantine, memory scan, threat intel updater, Flask UI/backend, and tests.
- `SysOptima_Sensor/`
  C++ Windows sensor project, solution, threat intelligence header, and local build output.
- `sysoptima_config.json`
  Main runtime configuration snapshot.
- `trust_config.json`
  Legacy/separate trust config.
- `sysoptima_events.db`
  Existing SQLite database file from prior runs.

## Intended Workflow

The intended end-to-end workflow appears to be:

1. The Windows sensor collects process, file, registry, memory, and network-related signals.
2. The sensor performs cheap/high-confidence checks first:
   hash hits, bad paths, masquerading, memory red flags, trust calculations, local cache lookups.
3. Events flow to Python over named pipes.
4. The Python Cortex translates raw events into semantic tags and stores process behavior in a graph.
5. Temporal logic and pattern matching raise threat confidence over time.
6. Trust-aware response logic decides whether to monitor, suspend, review, kill, or kill the process tree.
7. Quarantine and logging preserve evidence and allow later review.
8. AI is supposed to learn normal behavior and flag anomalies once enough baseline data exists.
9. A dashboard/API layer is supposed to let an operator inspect processes, pending reviews, and system status.

## What Looks Real vs Aspirational

More real / materially implemented:

- Python semantic tagging and temporal buffering in `Cortex/src/main.py`
- Trust engine in `Cortex/src/trust_engine.py`
- SQLite event database in `Cortex/src/database.py`
- Response orchestration in `Cortex/src/response_orchestrator.py`
- Quarantine manager in `Cortex/src/quarantine_manager.py`
- Flask API/backend in `Cortex/src/flask_backend.py`
- Static dashboard assets in `Cortex/src/templates` and `Cortex/src/static`
- C++ sensor core in `SysOptima_Sensor/.../SysOptima_Sensor.cpp`
- C++ memory scanning logic and process/threat handling in the sensor

Mostly aspirational, partial, or not fully wired:

- Kernel driver / Brain 0
- Fully working malware sandbox / isolated launcher
- Complete threat intelligence feed sync from Python to C++
- Robust signature validation and signer extraction
- Clean operator dashboard startup flow
- End-to-end polished deployment story
- Strong test coverage and verification across components

## Placeholder / Stub Inventory

The following areas are explicitly unfinished or misleadingly documented:

- `Cortex/src/main.py`
  File header says "production ready" and "feature complete", which does not match the repo state.
- `Cortex/README.md`
  Has been rewritten around the active Flask startup path, but should keep evolving as the launcher and runbook become more reliable.
- `Cortex/CORE_MODULES_IMPLEMENTED.md`
  Claims the system is 95% complete and production-ready. That is overstated relative to the code.
- `Cortex/src/memory_scanner.py`
  Signature verification is simplified and returns `True` as a placeholder after importing `wintrust`.
- `Cortex/src/memory_scanner.py`
  Memory alert generation comments say the event should go to the queue, but for now it is only logged.
- `Cortex/src/malware_launcher.py`
  Network activity collection returns placeholder data.
- `Cortex/src/malware_launcher.py`
  `_setup_network_isolation()` is placeholder-only.
- `Cortex/src/malware_launcher.py`
  `_setup_filesystem_isolation()` is placeholder-only.
- `Cortex/src/threat_intel.py`
  Hash/IP updates are not actually sent through the C++ control protocol; they are written to JSON files as a temporary workaround.
- `Cortex/src/trust_engine.py`
  Real signer extraction is still a TODO; current scoring gives a generic bonus for any valid signature.
- `SysOptima_Sensor/.../ThreatIntelligence.h`
  MalwareBazaar update path says "for now, just return true to show the structure works".
- `SysOptima_Sensor/.../ThreatIntelligence.h`
  VirusTotal integration is marked TODO / placeholder and reports "not yet implemented".
- `Cortex/src/simple_listener.py`
  Uses a different pipe name (`SysOptimaPipe`) and JSON listener flow that does not match the current binary named-pipe design in `main.py`. This looks like an older prototype file.
- `Cortex/src/dashboard_old.py`
  Legacy dashboard/test file with mock objects; not the current primary path.

## Important Mismatches

- Docs describe Brain 0 / kernel driver, but no driver source is present in this repository.
- Docs and README mention Dash dashboard components, but the repo currently contains Flask backend files and static assets instead.
- Some code assumes object-style process access, while some response code uses dict-style access. That suggests integration edges may still be brittle.
- The repo mixes "prototype", "interview/demo", and "target architecture" material in the same tree, so the documentation currently overstates delivery status.

## Non-Code Files That Matter

- `Docs/Complete Architecture`
  Best source for the final intended product and roadmap.
- `Docs/file structure.md`
  Best source for the original design decomposition.
- `Great questions.docx`
  Best source for your practical intent: reduce false positives, stage response actions, solve graph UX issues, and think carefully about safe AI training.
- `SysOptima_Interview_Guide.html`
  Best source for how you want to explain the project to others.

## My Read Of Your Intent

Your intent does not look like "just another antivirus". It looks like:

- Build a serious Windows EDR that uses behavior and context, not only signatures.
- Separate fast reflex logic from slower high-context reasoning.
- Use trust scoring to avoid the classic hobby-EDR problem of killing legitimate software.
- Add AI carefully as a late-stage amplification layer, not the only detector.
- Keep the system explainable enough to inspect through graphs, tags, and review queues.
- Eventually turn this into something impressive enough for research, demos, interviews, or a real product foundation.

## Recommended Next Reality-Based Milestones

If this repo is going to move from architecture-heavy to executable product, the next practical milestones should be:

1. Decide the real UI path: Flask UI or Dash, then remove the dead path.
2. Normalize the IPC contract between the C++ sensor and Python and delete obsolete listener code.
3. Finish threat-intel sync so Python can actually update the C++ cache.
4. Replace signature and isolation placeholders with real implementations or explicitly disable those claims.
5. Add a root-level startup path that actually works end to end.
6. Add a verification matrix: what runs today, what is stubbed, what is planned.
7. Remove generated build artifacts from version control if they are not intentionally kept.

## Bottom Line

This is a promising but incomplete EDR project with a strong architecture vision and a meaningful amount of prototype code already written. The main gap is not "no idea what to build"; the gap is that the repo currently mixes implemented modules, aspirational architecture, and interview/demo material without a single truthful status document.

This README is meant to be that truthful status document.
