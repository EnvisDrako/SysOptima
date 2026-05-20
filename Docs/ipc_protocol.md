# SysOptima IPC Protocol

This document describes the current named-pipe protocol between the C++ sensor and the Python Cortex.

Status: prototype protocol. It is documented here so future changes can be versioned instead of silently breaking parsing.

## Pipe Names

The C++ sensor creates two Windows named pipes:

- Data pipe: `\\.\pipe\SysOptimaData`
- Control pipe: `\\.\pipe\SysOptimaControl`

Direction:

- `SysOptimaData`: C++ sensor writes binary events, Python Cortex reads them.
- `SysOptimaControl`: Python Cortex writes binary commands, C++ sensor reads them.

## Encoding

- Struct packing is byte-aligned on the C++ side with `#pragma pack(push, 1)`.
- Python uses `struct` format strings with standard sizes and no alignment.
- Integer fields are currently little-endian in practice on Windows, but the Python format uses native-endian standard sizes. This should be made explicit in a future protocol version.
- Fixed-size string fields are UTF-8 bytes, null-padded.

## BinaryEvent

C++ source: `SysOptima_Sensor/SysOptima_Sensor/SysOptima_Sensor/SysOptima_Sensor.cpp`

Python source: `Cortex/src/protocol.py`

Python struct format:

```text
=IQIIIBiiii256s512s32s256s
```

Current size: `1097` bytes.

Fields:

| Field | C++ Type | Python Type | Size | Notes |
| --- | --- | --- | --- | --- |
| `event_type` | `uint32_t` | int | 4 | Event type enum |
| `timestamp` | `uint64_t` | int | 8 | Sensor timestamp |
| `pid` | `uint32_t` | int | 4 | Process ID |
| `ppid` | `uint32_t` | int | 4 | Parent process ID |
| `threat_level` | `uint32_t` | int | 4 | 0 safe, 1 suspicious, 2 critical |
| `is_signed` | `uint8_t` | bool | 1 | Signature status from sensor |
| `file_writes` | `uint32_t` | int | 4 | Aggregated file write count |
| `registry_writes` | `uint32_t` | int | 4 | Aggregated registry write count |
| `child_count` | `uint32_t` | int | 4 | Child process count |
| `network_connections` | `uint32_t` | int | 4 | Network connection count |
| `name` | `char[256]` | str | 256 | Process or event name |
| `full_path` | `char[512]` | str | 512 | Process/file path |
| `origin_tag` | `char[32]` | str | 32 | Origin label such as Internet/Local |
| `extra_data` | `char[256]` | str | 256 | Event-specific detail |

## Event Types

| Name | Value |
| --- | ---: |
| `EVT_PROCESS_START` | 1 |
| `EVT_PROCESS_END` | 2 |
| `EVT_FILE_WRITE` | 3 |
| `EVT_THREAT_DETECTED` | 4 |
| `EVT_REGISTRY_SET` | 5 |
| `EVT_MEMORY_ALERT` | 6 |
| `EVT_NETWORK_CONNECT` | 7 |
| `EVT_PROCESS_KILLED` | 8 |
| `EVT_AGGREGATED` | 9 |
| `EVT_BEACON_DETECTED` | 10 |

## BinaryCommand

Python struct format:

```text
=II256s
```

Current size: `264` bytes.

Fields:

| Field | C++ Type | Python Type | Size | Notes |
| --- | --- | --- | --- | --- |
| `cmd_type` | `uint32_t` | int | 4 | Command type enum |
| `target_pid` | `uint32_t` | int | 4 | Target PID, if applicable |
| `param` | `char[256]` | bytes/str | 256 | Optional command parameter |

## Command Types

| Name | Value | Status |
| --- | ---: | --- |
| `CMD_KILL_PID` | 1 | Implemented |
| `CMD_SUSPEND_PID` | 2 | Implemented |
| `CMD_KILL_TREE` | 3 | Implemented |
| `CMD_QUARANTINE` | 4 | Defined, integration incomplete |
| `CMD_CLEANUP_PERSISTENCE` | 5 | Defined, integration incomplete |
| `CMD_UPDATE_THREAT_CACHE` | 6 | Defined in C++, Python integration incomplete |

## Known Gaps

- No protocol version field or handshake exists yet.
- Python and C++ do not currently acknowledge command success/failure.
- Threat-cache update payloads are not specified.
- Reconnect behavior is basic and should be hardened.
- Endianness should be made explicit in a future format revision.

## Next Protocol Changes

Recommended next version:

- Add `protocol_version`.
- Add event sequence ID.
- Add command ID.
- Add command acknowledgement events.
- Use explicit little-endian format strings in Python once the C++ layout is updated or confirmed.
- Define structured payloads for threat-cache updates.
