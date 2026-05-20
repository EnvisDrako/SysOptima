import struct
import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from protocol import (  # noqa: E402
    BINARY_COMMAND_FORMAT,
    BINARY_COMMAND_SIZE,
    BINARY_EVENT_FORMAT,
    BINARY_EVENT_SIZE,
    CMD_KILL_PID,
    EVT_PROCESS_START,
    pack_command,
    parse_binary_event,
)


def fixed(value, size):
    return value.encode("utf-8")[:size].ljust(size, b"\x00")


class ProtocolTests(unittest.TestCase):
    def test_event_size_matches_documented_cpp_layout(self):
        self.assertEqual(BINARY_EVENT_SIZE, 1097)
        self.assertEqual(struct.calcsize(BINARY_EVENT_FORMAT), BINARY_EVENT_SIZE)

    def test_command_size_matches_documented_cpp_layout(self):
        self.assertEqual(BINARY_COMMAND_SIZE, 264)
        self.assertEqual(struct.calcsize(BINARY_COMMAND_FORMAT), BINARY_COMMAND_SIZE)

    def test_parse_binary_event(self):
        raw = struct.pack(
            BINARY_EVENT_FORMAT,
            EVT_PROCESS_START,
            123456789,
            4242,
            1000,
            1,
            1,
            5,
            2,
            3,
            4,
            fixed("demo.exe", 256),
            fixed(r"C:\Temp\demo.exe", 512),
            fixed("Internet", 32),
            fixed("example", 256),
        )

        event = parse_binary_event(raw)

        self.assertEqual(event["event_type"], EVT_PROCESS_START)
        self.assertEqual(event["pid"], 4242)
        self.assertTrue(event["is_signed"])
        self.assertEqual(event["name"], "demo.exe")
        self.assertEqual(event["full_path"], r"C:\Temp\demo.exe")
        self.assertEqual(event["origin_tag"], "Internet")
        self.assertEqual(event["extra_data"], "example")

    def test_parse_binary_event_rejects_incomplete_data(self):
        self.assertIsNone(parse_binary_event(b"\x00" * (BINARY_EVENT_SIZE - 1)))

    def test_pack_command(self):
        raw = pack_command(CMD_KILL_PID, 4242, "reason")
        cmd_type, target_pid, param = struct.unpack(BINARY_COMMAND_FORMAT, raw)

        self.assertEqual(cmd_type, CMD_KILL_PID)
        self.assertEqual(target_pid, 4242)
        self.assertEqual(param.rstrip(b"\x00"), b"reason")


if __name__ == "__main__":
    unittest.main()
