# SysOptima Sentinel - Enterprise EDR Console & Sensor

SysOptima Sentinel is a high-fidelity, hybrid Endpoint Detection and Response (EDR) platform designed for Windows enterprise clients. Instead of relying purely on signature matching, the system integrates a real-time behavioral graph engine, Authenticode signature trust verification caching, and graduated surgical mitigations to detect, contain, and analyze endpoint threats with minimal system overhead.

---

## 🏗️ Systems Architecture Overview

The platform is split into two cleanly decoupled layers that communicate over a secure, hardened IPC channel:

1. **C++ elevated Telemetry Sensor (`SysOptima_Sensor`)**:
   * Runs in elevated privilege contexts (`SYSTEM` or Administrator) to hook core Windows trace events.
   * Utilizes **KrabsETW** for low-overhead kernel tracing of process creations, file modifications, registry changes, and outbound network sockets.
   * Packages and serializes event data before streaming it over a highly secured Named Pipe IPC boundary (`\\.\pipe\SysOptimaData`).

2. **Python Cortex Analytics & Response Engine (`Cortex`)**:
   * Consumes incoming telemetry events, running them through a thread-safe sliding-window filter to deduplicate redundant events.
   * Maintains a live, memory-optimized directed process tree graph (`networkx`).
   * Validates executable digital signers and caches the trust verdict to achieve sub-millisecond future trace speeds.
   * Calculates structural and behavior threat scores, managing graduated mitigations (suspend threads, Smart Tree termination, Win32 memory minidumping, and firewall isolation blocks).
   * Exposes a glassmorphic visual tactical dashboard served over WebSockets (`Flask-SocketIO`).

---

## 🛠️ Prerequisites

* **Operating System**: Windows 10 / 11 (64-bit).
* **Compiler**: Microsoft Visual Studio (MSVC) Build Tools supporting the C++17 standard (`/std:c++17`).
* **Runtime**: Python 3.8 or higher.
* **Privileges**: Elevated Administrator privileges are required to register kernel trace providers and bind named pipes.

---

## 🚀 Installation & Build Guide

### 1. Compile the C++ Telemetry Agent
Navigate to the root project directory and build the Release configuration targeting x64 architectures using MSBuild:
```powershell
MSBuild.exe .\SysOptima_Sensor\SysOptima_Sensor.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64
```
This compiles the elevated sensor executable inside `SysOptima_Sensor\SysOptima_Sensor\x64\Release\SysOptima_Sensor.exe`.

### 2. Set Up the Python Cortex Dependencies
Navigate to the Cortex project folder and install the required library packages:
```powershell
cd Cortex
python -m pip install -r requirements.txt
```

---

## 🏁 Operational Launch Steps

To establish the secure Named Pipe IPC pipe and trace active processes, launch both agents from elevated command prompts:

### Step 1: Start the Python Cortex Core Backend
Open an **elevated Administrator PowerShell prompt** in the Cortex source directory and execute the core application runner:
```powershell
cd Cortex\src
python main.py
```
*This starts the Flask dashboard server on `http://127.0.0.1:8050` and establishes the security-hardened Named Pipe server, waiting for telemetry connections.*

### Step 2: Launch the C++ Telemetry Sensor Agent
Open a **second elevated Administrator prompt**, navigate to the compiled binary directory, and launch the sensor:
```powershell
cd SysOptima_Sensor\SysOptima_Sensor\x64\Release
.\SysOptima_Sensor.exe
```
*The sensor hooks onto the active Named Pipe and instantly begins streaming process, filesystem, and socket events to the backend.*

### Step 3: Access the Visual Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:8050
```
Use the glassmorphic dashboard to monitor active task lineages, search nodes in real-time, launch sandboxed bat executions in the **Detonation Lab**, or inspect isolated files in the **Quarantine Vault**.

---

## 🔒 Security & IPC Integrity

To ensure unprivileged user processes cannot hijack EDR logging pipes or inject forged white-lists, all Named Pipes are initialized with a strict **Security Descriptor Definition Language (SDDL)** configuration:
```
D:(A;;GA;;;SY)(A;;GA;;;BA)
```
* **SY (SYSTEM)**: Grants local system kernel agents Generic All (GA) access.
* **BA (Built-in Administrators)**: Grants local administrators Generic All (GA) access.
* All standard non-elevated user contexts attempting to query or write to these pipes are immediately blocked by the Windows NT kernel with `ERROR_ACCESS_DENIED`.

---

## 🧪 Operational Testing & Diagnostics

Both automated unit tests and behavior tree correlation tests can be run locally inside `Cortex\src` to confirm agent stability:
```powershell
# Run EDR modular unit test suites
python test_modules.py

# Run EDR process spawn threat tree correlation tests
python test_graph_processor.py
```
*These tests run in zero-admin contexts, safely overriding directories and registry roots to localized temp paths.*
