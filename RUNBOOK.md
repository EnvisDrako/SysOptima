# SysOptima Prototype Runbook

This runbook describes the current active prototype flow. It does not claim production deployment readiness.

## Prerequisites

- Windows.
- Python 3.10+ recommended.
- Visual Studio with C++ tooling for the sensor project.
- Administrator privileges may be required for some ETW, process, memory, suspend, kill, and quarantine behavior.

## Install Cortex Dependencies

```powershell
cd D:\SysOptima\Cortex
python -m pip install -r requirements.txt
```

## Build The C++ Sensor

Open the existing Visual Studio solution/workspace:

```text
D:\SysOptima\SysOptima_Sensor\SysOptima_Sensor\SysOptima_Sensor.slnx
```

Build the `SysOptima_Sensor` project for x64 Debug or the desired local configuration. The C++/Krabs workflow is intentionally kept in Visual Studio.

## Start The Sensor

Start the sensor before Cortex so it can create the named pipes:

```text
\\.\pipe\SysOptimaData
\\.\pipe\SysOptimaControl
```

The exact executable path depends on the Visual Studio build configuration.

## Start Cortex

```powershell
cd D:\SysOptima\Cortex\src
python launch.py
```

Cortex starts:

- SQLite event database
- AI observer
- threat graph
- response orchestrator
- memory scanner, if enabled
- quarantine manager
- named-pipe reader/writer threads
- Flask dashboard

The dashboard URL is printed during startup. The default is:

```text
http://localhost:8050
```

## Run Protocol Tests

These tests do not require the C++ sensor:

```powershell
cd D:\SysOptima
python -m unittest discover -s Cortex\tests
```

## Stop The Prototype

- Stop Cortex with `Ctrl+C` in the Python terminal.
- Stop the C++ sensor from its terminal, Visual Studio debugger, or Task Manager if necessary.

## Current Caveats

- The IPC protocol has no version handshake yet.
- The dashboard binds to `0.0.0.0` in the current Flask backend; production/local-only behavior still needs hardening.
- Threat-intel cache updates are not fully wired.
- Malware launcher isolation is placeholder-only and should not be treated as a safe sandbox.
- Several runtime paths still assume Windows and pywin32.
