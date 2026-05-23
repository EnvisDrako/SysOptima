"""
SysOptima Memory Scanner with Trust-Based Whitelisting
Prevents false positives by checking trust scores before flagging RWX memory
"""

import time
import psutil
import win32api
import win32process
import win32con
from typing import Dict, List, Optional, Tuple
import struct
import threading
from collections import defaultdict
import ctypes
from ctypes import wintypes

# Define the GUID structure for WinVerifyTrust
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_byte * 8)
    ]

# Define the WINTRUST_FILE_INFO structure
class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p)
    ]

# Define the WINTRUST_DATA structure
class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.c_void_p),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p)
    ]

# WinTrust Constants
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2

# WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00aac56b, 0xcd44, 0x11d0,
    (ctypes.c_byte * 8)(0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee)
)

class MemoryScanner:
    """Trust-aware memory scanner that prevents false positives"""
    
    def __init__(self, trust_engine, config_manager, event_queue=None):
        self.trust_engine = trust_engine
        self.config = config_manager
        self.event_queue = event_queue
        self.scan_interval = config_manager.get('detection.memory_scan_interval_ms', 10000) / 1000.0
        self.trust_threshold_skip = config_manager.get('trust.trust_threshold_skip_scan', 40)
        self.skip_trusted = config_manager.get('trust.skip_memory_scan_for_trusted', True)
        
        # Known legitimate processes that use RWX memory
        self.jit_processes = {
            'chrome.exe', 'msedge.exe', 'firefox.exe',  # Browsers (V8, SpiderMonkey)
            'java.exe', 'javaw.exe',                     # Java JIT
            'dotnet.exe', 'w3wp.exe',                    # .NET JIT
            'node.exe', 'electron.exe',                  # Node.js V8
            'python.exe', 'pythonw.exe',                # Python JIT (PyPy)
            'code.exe',                                  # VSCode (Electron)
            'discord.exe', 'slack.exe', 'teams.exe',    # Electron apps
            'steam.exe', 'steamwebhelper.exe',          # Steam (Chromium)
            'spotify.exe',                               # Spotify (Chromium)
        }
        
        # Memory patterns that are suspicious
        self.suspicious_patterns = {
            'UNBACKED_EXEC': 'Executable memory with no file backing',
            'PRIVATE_RWX': 'Private RWX allocation (potential shellcode)',
            'MODIFIED_PE': 'PE header modifications detected',
            'HOLLOW_PROCESS': 'Process memory replaced (process hollowing)',
            'THREAD_INJECTION': 'Remote thread in process memory',
            'APC_INJECTION': 'APC queue injection detected'
        }
        
        # Process memory cache (avoid repeated scans)
        self.memory_cache = {}
        self.cache_timeout = 30  # seconds
        
        # Statistics
        self.stats = {
            'scans_performed': 0,
            'processes_skipped_trust': 0,
            'processes_skipped_jit': 0,
            'suspicious_memory_found': 0,
            'false_positives_prevented': 0
        }
        
        self.running = False
        self.scan_thread = None
    
    def start_scanning(self):
        """Start background memory scanning"""
        if self.running:
            return
        
        self.running = True
        self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scan_thread.start()
        print(f"[MEMORY] Scanner started (interval: {self.scan_interval}s)")
    
    def stop_scanning(self):
        """Stop background memory scanning"""
        self.running = False
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        print("[MEMORY] Scanner stopped")
        
    def scan_process(self, pid: int, name: str, exe_path: str):
        """Trigger a targeted memory scan for a single process (typically on startup)"""
        if self._should_skip_process(pid, name, exe_path):
            return
            
        findings = self._scan_process_memory(pid, name, exe_path)
        if findings:
            self._handle_suspicious_memory(pid, name, exe_path, findings)
    
    def _scan_loop(self):
        """Main scanning loop"""
        while self.running:
            try:
                self._scan_all_processes()
                time.sleep(self.scan_interval)
            except Exception as e:
                print(f"[MEMORY] Scan error: {e}")
                time.sleep(5)  # Wait before retrying
    
    def _scan_all_processes(self):
        """Scan memory of all running processes"""
        start_time = time.monotonic()
        scanned_count = 0
        skipped_count = 0
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                if not self.running:
                    break
                
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    exe_path = proc.info['exe']
                    
                    # Skip system processes
                    if pid <= 4 or name in ['System', 'Registry']:
                        continue
                    
                    # Check if we should skip this process
                    if self._should_skip_process(pid, name, exe_path):
                        skipped_count += 1
                        continue
                    
                    # Scan process memory
                    findings = self._scan_process_memory(pid, name, exe_path)
                    if findings:
                        self._handle_suspicious_memory(pid, name, exe_path, findings)
                    
                    scanned_count += 1
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    print(f"[MEMORY] Error scanning PID {pid}: {e}")
                    continue
        
        except Exception as e:
            print(f"[MEMORY] Process enumeration error: {e}")
        
        scan_time = time.monotonic() - start_time
        self.stats['scans_performed'] += 1
        
        if scanned_count > 0 or skipped_count > 0:
            print(f"[MEMORY] Scan complete: {scanned_count} scanned, {skipped_count} skipped ({scan_time:.2f}s)")
    
    def _should_skip_process(self, pid: int, name: str, exe_path: str) -> bool:
        """Determine if process should be skipped based on trust"""
        
        # Skip if in JIT whitelist
        if name.lower() in self.jit_processes:
            self.stats['processes_skipped_jit'] += 1
            return True
        
        # Skip if trust-based scanning is enabled and process is trusted
        if self.skip_trusted and exe_path:
            try:
                process_info = {
                    'name': name,
                    'full_path': exe_path,
                    'is_signed': self._is_process_signed(exe_path),
                    'origin': 'System' if exe_path.startswith('C:\\Windows\\') else 'User'
                }
                
                trust_score = self.trust_engine.calculate_trust_score(process_info)
                
                if trust_score >= self.trust_threshold_skip:
                    self.stats['processes_skipped_trust'] += 1
                    print(f"[MEMORY] Skipping trusted process: {name} (trust: {trust_score})")
                    return True
                    
            except Exception as e:
                print(f"[MEMORY] Trust calculation error for {name}: {e}")
        
        return False
    
    def _scan_process_memory(self, pid: int, name: str, exe_path: str) -> List[Dict]:
        """Scan specific process for suspicious memory patterns"""
        
        # Check cache first
        cache_key = f"{pid}_{name}"
        now = time.monotonic()
        
        if cache_key in self.memory_cache:
            cache_entry = self.memory_cache[cache_key]
            if now - cache_entry['timestamp'] < self.cache_timeout:
                return cache_entry['findings']
        
        findings = []
        
        try:
            # Open process with memory read access
            h_process = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False, pid
            )
            
            if not h_process:
                return findings
            
            try:
                # Scan memory regions
                findings = self._analyze_memory_regions(h_process, pid, name)
                
                # Cache results
                self.memory_cache[cache_key] = {
                    'timestamp': now,
                    'findings': findings
                }
                
                # Clean old cache entries
                self._cleanup_cache(now)
                
            finally:
                win32api.CloseHandle(h_process)
                
        except Exception as e:
            print(f"[MEMORY] Failed to scan PID {pid}: {e}")
        
        return findings
    
    def _analyze_memory_regions(self, h_process, pid: int, name: str) -> List[Dict]:
        """Analyze memory regions for suspicious patterns across 64-bit address space"""
        findings = []
        
        try:
            import win32process
            
            # Get memory info across 64-bit user space range
            address = 0
            consecutive_failures = 0
            while address < 0x7FFFFFFFFFFF:  # 64-bit Windows user space limit
                try:
                    mbi = win32process.VirtualQueryEx(h_process, address)
                    consecutive_failures = 0
                    
                    if not mbi or mbi.RegionSize <= 0:
                        break
                    
                    # Check for suspicious memory patterns
                    if self._is_suspicious_memory(mbi, h_process, address):
                        finding = self._analyze_memory_region(mbi, h_process, address, pid, name)
                        if finding:
                            findings.append(finding)
                    
                    # Move to next region
                    address = mbi.BaseAddress + mbi.RegionSize
                    
                except Exception:
                    consecutive_failures += 1
                    if consecutive_failures > 10:  # Prevent infinite loop in high unallocated addresses
                        break
                    address += 0x10000  # Skip 64KB (Windows allocation granularity) and continue
                    
        except Exception as e:
            print(f"[MEMORY] Memory analysis error for PID {pid}: {e}")
        
        return findings
    
    def _is_suspicious_memory(self, mbi, h_process, address) -> bool:
        """Check if memory region is suspicious"""
        
        # Only scan committed memory pages. Skip MEM_FREE and MEM_RESERVE completely.
        if getattr(mbi, 'State', 0) != win32con.MEM_COMMIT:
            return False
            
        # Check for RWX (Read-Write-Execute) memory
        if (mbi.Protect & win32con.PAGE_EXECUTE_READWRITE) or \
           (mbi.Protect & win32con.PAGE_EXECUTE_WRITECOPY):
            return True
        
        # Check for executable memory that's not backed by a file
        if (mbi.Protect & (win32con.PAGE_EXECUTE | win32con.PAGE_EXECUTE_READ)) and \
           mbi.Type == win32con.MEM_PRIVATE:
            return True
        
        return False
    
    def _analyze_memory_region(self, mbi, h_process, address, pid: int, name: str) -> Optional[Dict]:
        """Analyze specific memory region for threats"""
        
        try:
            # Read memory content
            buffer = win32process.ReadProcessMemory(h_process, address, min(mbi.RegionSize, 4096))
            
            finding = {
                'pid': pid,
                'process_name': name,
                'address': hex(address),
                'size': mbi.RegionSize,
                'protection': mbi.Protect,
                'type': mbi.Type,
                'patterns': [],
                'threat_level': 0
            }
            
            # Check for PE header modifications
            if self._check_pe_modifications(buffer):
                finding['patterns'].append('MODIFIED_PE')
                finding['threat_level'] += 30
            
            # Check for shellcode patterns
            if self._check_shellcode_patterns(buffer):
                finding['patterns'].append('PRIVATE_RWX')
                finding['threat_level'] += 40
            
            # Check if unbacked executable
            if mbi.Type == win32con.MEM_PRIVATE and \
               (mbi.Protect & (win32con.PAGE_EXECUTE | win32con.PAGE_EXECUTE_READ)):
                finding['patterns'].append('UNBACKED_EXEC')
                finding['threat_level'] += 35
            
            # Only return if we found something suspicious
            if finding['patterns']:
                return finding
                
        except Exception as e:
            print(f"[MEMORY] Region analysis error at {hex(address)}: {e}")
        
        return None
    
    def _check_pe_modifications(self, buffer: bytes) -> bool:
        """Check for PE header modifications (basic check)"""
        if len(buffer) < 64:
            return False
        
        # Check for MZ header
        if buffer[:2] == b'MZ':
            try:
                # Get PE offset
                pe_offset = struct.unpack('<I', buffer[60:64])[0]
                if pe_offset < len(buffer) - 4:
                    # Check for PE signature
                    if buffer[pe_offset:pe_offset+2] == b'PE':
                        # This is a valid PE - check if it's been modified
                        # (This is a simplified check - real implementation would be more thorough)
                        return False
            except:
                pass
        
        # If we can't parse it properly, it might be modified
        return True
    
    def _check_shellcode_patterns(self, buffer: bytes) -> bool:
        """Check for common shellcode patterns"""
        if len(buffer) < 16:
            return False
        
        # Common shellcode patterns (simplified)
        shellcode_patterns = [
            b'\x90\x90\x90\x90',  # NOP sled
            b'\x31\xc0',          # xor eax, eax
            b'\x50\x68',          # push/push pattern
            b'\xff\xe4',          # jmp esp
            b'\xeb\xfe',          # jmp $-2 (infinite loop)
        ]
        
        for pattern in shellcode_patterns:
            if pattern in buffer:
                return True
        
        return False
    
    def _cleanup_cache(self, current_time: float):
        """Remove old cache entries"""
        to_remove = []
        for key, entry in self.memory_cache.items():
            if current_time - entry['timestamp'] > self.cache_timeout:
                to_remove.append(key)
        
        for key in to_remove:
            del self.memory_cache[key]
    
    def _is_process_signed(self, exe_path: str) -> bool:
        """Check if process executable is digitally signed using WinVerifyTrust"""
        if not exe_path:
            return False
        try:
            wintrust = ctypes.windll.wintrust
            
            file_info = WINTRUST_FILE_INFO()
            file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            file_info.pcwszFilePath = exe_path
            file_info.hFile = None
            file_info.pgKnownSubject = None
            
            trust_data = WINTRUST_DATA()
            trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            trust_data.pPolicyCallbackData = None
            trust_data.pSIPClientData = None
            trust_data.dwUIChoice = WTD_UI_NONE
            trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
            trust_data.dwUnionChoice = WTD_CHOICE_FILE
            trust_data.pFile = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
            trust_data.dwStateAction = WTD_STATEACTION_VERIFY
            trust_data.hWVTStateData = None
            trust_data.pwszURLReference = None
            trust_data.dwProvFlags = 0
            trust_data.dwUIContext = 0
            trust_data.pSignatureSettings = None
            
            # Call WinVerifyTrust to verify signature
            status = wintrust.WinVerifyTrust(
                None,
                ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(trust_data)
            )
            
            # Close the WVT state data
            trust_data.dwStateAction = WTD_STATEACTION_CLOSE
            wintrust.WinVerifyTrust(
                None,
                ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(trust_data)
            )
            
            return status == 0
        except Exception as e:
            print(f"[MEMORY] Signature verification exception: {e}")
            return False
    
    def _handle_suspicious_memory(self, pid: int, name: str, exe_path: str, findings: List[Dict]):
        """Handle suspicious memory findings"""
        
        self.stats['suspicious_memory_found'] += len(findings)
        
        for finding in findings:
            threat_level = finding['threat_level']
            patterns = finding['patterns']
            
            # Calculate final trust score to determine if this is a false positive
            try:
                process_info = {
                    'name': name,
                    'full_path': exe_path,
                    'is_signed': self._is_process_signed(exe_path),
                    'origin': 'System' if exe_path.startswith('C:\\Windows\\') else 'User'
                }
                
                trust_score = self.trust_engine.calculate_trust_score(process_info)
                
                # Adjust threat based on trust
                if trust_score >= 40:
                    # High trust - likely false positive
                    print(f"[MEMORY] Suspicious memory in trusted process {name} (PID {pid}) - trust: {trust_score}")
                    print(f"         Patterns: {patterns} - ALLOWING due to high trust")
                    self.stats['false_positives_prevented'] += 1
                    continue
                elif trust_score >= 0:
                    # Medium trust - reduce threat level
                    threat_level = max(0, threat_level - 20)
                    print(f"[MEMORY] Suspicious memory in {name} (PID {pid}) - trust: {trust_score}, reduced threat: {threat_level}")
                else:
                    # Low trust - increase threat level
                    threat_level += 10
                    print(f"[MEMORY] Suspicious memory in untrusted {name} (PID {pid}) - trust: {trust_score}, increased threat: {threat_level}")
                
            except Exception as e:
                print(f"[MEMORY] Trust calculation error: {e}")
            
            # Report finding if still suspicious
            if threat_level >= 30:
                self._report_memory_threat(pid, name, exe_path, finding, trust_score)
    
    def _report_memory_threat(self, pid: int, name: str, exe_path: str, finding: Dict, trust_score: int):
        """Report memory threat to main system"""
        
        print(f"[MEMORY] 🚨 THREAT: {name} (PID {pid})")
        print(f"         Address: {finding['address']}, Size: {finding['size']} bytes")
        print(f"         Patterns: {finding['patterns']}")
        print(f"         Threat Level: {finding['threat_level']}, Trust: {trust_score}")
        
        # Create memory alert event (this would be sent to the main threat graph)
        memory_event = {
            'event_type': 6,  # EVT_MEMORY_ALERT
            'timestamp': int(time.time() * 1000),
            'pid': pid,
            'ppid': 0,
            'threat_level': min(finding['threat_level'] // 40, 2),  # Convert to 0-2 scale
            'is_signed': self._is_process_signed(exe_path),
            'file_writes': 0,
            'registry_writes': 0,
            'child_count': 0,
            'network_connections': 0,
            'name': name,
            'full_path': exe_path,
            'origin_tag': 'Memory',
            'extra_data': f"Memory patterns: {', '.join(finding['patterns'])}"
        }
        
        # Send memory alert event to the main threat graph if queue is available
        if self.event_queue:
            self.event_queue.put(memory_event)
            print(f"[MEMORY] Queued memory alert event for {name}")
        else:
            print(f"[MEMORY] Generated memory alert event for {name} (no queue connected)")
    
    def get_statistics(self) -> Dict:
        """Get memory scanner statistics"""
        return {
            **self.stats,
            'cache_size': len(self.memory_cache),
            'scan_interval': self.scan_interval,
            'trust_threshold': self.trust_threshold_skip,
            'skip_trusted_enabled': self.skip_trusted
        }
    
    def force_scan_process(self, pid: int) -> List[Dict]:
        """Force scan a specific process (bypass trust checks)"""
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            exe_path = proc.exe()
            
            print(f"[MEMORY] Force scanning {name} (PID {pid})")
            findings = self._scan_process_memory(pid, name, exe_path)
            
            if findings:
                print(f"[MEMORY] Found {len(findings)} suspicious memory regions")
                for finding in findings:
                    print(f"         {finding['address']}: {finding['patterns']}")
            else:
                print(f"[MEMORY] No suspicious memory found in {name}")
            
            return findings
            
        except Exception as e:
            print(f"[MEMORY] Force scan error: {e}")
            return []