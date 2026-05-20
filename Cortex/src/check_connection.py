"""
Quick diagnostic tool to check if C++ Sentinel is running and pipes are accessible
"""

import win32file
import win32pipe
import pywintypes
import time

from protocol import PIPE_DATA_NAME, PIPE_CTRL_NAME

def check_pipe(pipe_name):
    """Try to connect to a named pipe"""
    print(f"\nChecking: {pipe_name}")
    try:
        # Try to open the pipe
        handle = win32file.CreateFile(
            pipe_name,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        print(f"  ✓ SUCCESS - Pipe exists and is accessible!")
        win32file.CloseHandle(handle)
        return True
    except pywintypes.error as e:
        error_code = e.winerror
        if error_code == 2:  # ERROR_FILE_NOT_FOUND
            print(f"  ✗ FAILED - Pipe does not exist")
            print(f"    → C++ Sentinel may not be running or pipes not created")
        elif error_code == 231:  # ERROR_PIPE_BUSY
            print(f"  ✓ Pipe exists but is busy (already connected)")
        else:
            print(f"  ✗ FAILED - Error code: {error_code}")
            print(f"    Error: {e}")
        return False

def main():
    print("="*60)
    print("  SYSOPTIMA CONNECTION DIAGNOSTIC")
    print("="*60)
    
    # Check if C++ process is running
    import subprocess
    try:
        result = subprocess.run(
            ['powershell', '-Command', 
             'Get-Process | Where-Object {$_.ProcessName -like "*SysOptima*"} | Select-Object ProcessName,Id'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if "SysOptima" in result.stdout:
            print("\n✓ C++ Sentinel process is RUNNING")
            print(result.stdout)
        else:
            print("\n✗ C++ Sentinel process NOT FOUND")
            print("\n  ACTION REQUIRED:")
            print("  1. Open PowerShell as Administrator")
            print("  2. Navigate to: d:\\SysOptima\\SysOptima_Sensor\\SysOptima_Sensor\\x64\\Release")
            print("  3. Run: .\\SysOptima_Sensor.exe")
            print("\n  Then re-run this diagnostic.")
            return
    except Exception as e:
        print(f"\n! Could not check for C++ process: {e}")
    
    # Check pipes
    data_ok = check_pipe(PIPE_DATA_NAME)
    ctrl_ok = check_pipe(PIPE_CTRL_NAME)
    
    print("\n" + "="*60)
    if data_ok and ctrl_ok:
        print("  ✓ ALL CHECKS PASSED - Ready to connect!")
        print("="*60)
        print("\nYou can now run: python src/main.py")
    elif not data_ok or not ctrl_ok:
        print("  ✗ CONNECTION NOT READY")
        print("="*60)
        print("\nDIAGNOSIS:")
        print("  C++ Sentinel is running but pipes are not created.")
        print("\nPOSSIBLE CAUSES:")
        print("  1. C++ crashed during startup (check its window for errors)")
        print("  2. C++ needs Administrator privileges")
        print("  3. C++ build is outdated")
        print("\nSOLUTIONS:")
        print("  1. Close C++ (if running)")
        print("  2. Rebuild in Visual Studio (Release mode)")
        print("  3. Run as Administrator:")
        print("     Right-click SysOptima_Sensor.exe → Run as Administrator")
        print("\n  Then re-run this diagnostic.")
    print()

if __name__ == "__main__":
    main()
