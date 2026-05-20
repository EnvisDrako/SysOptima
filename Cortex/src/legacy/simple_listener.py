import time
import win32file
import win32pipe

# Pipe Name must match the C++ code exactly
PIPE_NAME = r'\\.\pipe\SysOptimaPipe'

print(f"[*] Connecting to C++ Pipe: {PIPE_NAME}...")

while True:
    try:
        # Connect to the pipe created by C++
        handle = win32file.CreateFile(
            PIPE_NAME,
            win32file.GENERIC_READ,
            0, None,
            win32file.OPEN_EXISTING,
            0, None
        )
        print("[+] Connected! Listening for JSON events...")
        break
    except Exception as e:
        print(f"[*] Waiting for C++ Sensor... ({e})")
        time.sleep(2)

# Read Loop
while True:
    try:
        # Read data from pipe (Buffer size 4096)
        result, data = win32file.ReadFile(handle, 4096)
        
        # Decode bytes to string
        message = data.decode('utf-8').strip()
        
        if message:
            print(f"[RECV] {message}")
            
    except Exception as e:
        print(f"[!] Pipe Broken: {e}")
        break