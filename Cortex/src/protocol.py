"""
Binary IPC protocol shared by the Python Cortex and the C++ sensor.

The layouts in this module must match BinaryEvent and BinaryCommand in
SysOptima_Sensor.cpp.
"""

import struct
from typing import Dict, Optional, Union

PIPE_DATA_NAME = r"\\.\pipe\SysOptimaData"
PIPE_CTRL_NAME = r"\\.\pipe\SysOptimaControl"

BINARY_EVENT_FORMAT = "=IQIIIBiiii256s512s32s256s"
BINARY_EVENT_SIZE = struct.calcsize(BINARY_EVENT_FORMAT)

BINARY_COMMAND_FORMAT = "=II256s"
BINARY_COMMAND_SIZE = struct.calcsize(BINARY_COMMAND_FORMAT)

# Event types. Must match the C++ EventType enum.
EVT_PROCESS_START = 1
EVT_PROCESS_END = 2
EVT_FILE_WRITE = 3
EVT_THREAT_DETECTED = 4
EVT_REGISTRY_SET = 5
EVT_MEMORY_ALERT = 6
EVT_NETWORK_CONNECT = 7
EVT_PROCESS_KILLED = 8
EVT_AGGREGATED = 9
EVT_BEACON_DETECTED = 10

# Command types. Must match the C++ CommandType enum.
CMD_KILL_PID = 1
CMD_SUSPEND_PID = 2
CMD_KILL_TREE = 3
CMD_QUARANTINE = 4
CMD_CLEANUP_PERSISTENCE = 5
CMD_UPDATE_THREAT_CACHE = 6
CMD_SET_MODE = 7


def _decode_fixed_string(value: bytes) -> str:
    return value.decode("utf-8", errors="ignore").rstrip("\x00")


def _encode_fixed_string(value: Union[str, bytes], size: int = 256) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8", errors="ignore")
    return value[:size].ljust(size, b"\x00")


def parse_binary_event(data: bytes) -> Optional[Dict]:
    """Parse one BinaryEvent. Returns None when data is incomplete or invalid."""
    if len(data) < BINARY_EVENT_SIZE:
        return None

    try:
        parts = struct.unpack(BINARY_EVENT_FORMAT, data[:BINARY_EVENT_SIZE])
    except struct.error:
        return None

    return {
        "event_type": parts[0],
        "timestamp": parts[1],
        "pid": parts[2],
        "ppid": parts[3],
        "threat_level": parts[4],
        "is_signed": bool(parts[5]),
        "file_writes": parts[6],
        "registry_writes": parts[7],
        "child_count": parts[8],
        "network_connections": parts[9],
        "name": _decode_fixed_string(parts[10]),
        "full_path": _decode_fixed_string(parts[11]),
        "origin_tag": _decode_fixed_string(parts[12]),
        "extra_data": _decode_fixed_string(parts[13]),
    }


def pack_command(cmd_type: int, target_pid: int, param: Union[str, bytes] = b"") -> bytes:
    """Pack a BinaryCommand for the C++ control pipe."""
    return struct.pack(
        BINARY_COMMAND_FORMAT,
        int(cmd_type),
        int(target_pid),
        _encode_fixed_string(param, 256),
    )
