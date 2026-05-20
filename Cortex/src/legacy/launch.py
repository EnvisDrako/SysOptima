"""
SysOptima Cortex launcher.

This is intentionally thin: main.py owns application composition, worker
startup, and the active Flask dashboard. Keeping this file small prevents
startup drift between multiple entry points.
"""

from main import main as start_cortex


def main():
    print("=" * 70)
    print("  SYSOPTIMA EDR - Cortex Launcher")
    print("=" * 70)
    print()
    print("Active components:")
    print("  1. SQLite event database")
    print("  2. AI observer")
    print("  3. Threat graph and response orchestrator")
    print("  4. Named-pipe client for the C++ sensor")
    print("  5. Flask dashboard from flask_backend.py")
    print()
    print("Prerequisites:")
    print("  - Run on Windows with pywin32 installed.")
    print("  - Start the C++ sensor first for live named-pipe events.")
    print("  - Use the dashboard URL printed by main.py after startup.")
    print()
    return start_cortex()


if __name__ == "__main__":
    raise SystemExit(main())
