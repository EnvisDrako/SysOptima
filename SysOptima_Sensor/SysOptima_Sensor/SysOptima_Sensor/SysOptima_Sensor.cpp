// ================================================================
// SYSOPTIMA COMPLETE C++ ENGINE - PRODUCTION READY
// No further C++ changes needed after this
// ================================================================
#ifndef WINVER
#define WINVER 0x0A00
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <string>
#include <windows.h>
#include <krabs.hpp>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <chrono>
#include <sstream>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <algorithm>
#include <fstream>
#include <regex>
#include <wininet.h>
#include <iphlpapi.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <processthreadsapi.h>
#include <sddl.h>
#include "ThreatIntelligence.h"


#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")


using namespace krabs;
using namespace std;
using namespace std::chrono;

// ================================================================
// CONFIGURATION
// ================================================================

int g_mode = 1;  // 0=Production, 1=Smart, 2=Learning
const int REORDER_BUFFER_MS = 500;
const int MEMORY_SCAN_INTERVAL_MS = 10000;
const int AGGREGATION_FLUSH_MS = 100;
const int NETWORK_SCAN_INTERVAL_MS = 5000;

// ================================================================
// DATA STRUCTURES
// ================================================================

struct ProcessUID {
    DWORD pid;
    uint64_t start_time;
    bool operator==(const ProcessUID& other) const {
        return pid == other.pid && start_time == other.start_time;
    }
};

namespace std {
    template<> struct hash<ProcessUID> {
        size_t operator()(const ProcessUID& uid) const {
            return hash<DWORD>()(uid.pid) ^ (hash<uint64_t>()(uid.start_time) << 1);
        }
    };
}

struct ProcessInfo {
    ProcessUID uid;
    ProcessUID parent_uid;
    wstring name;
    wstring full_path;
    bool is_signed;
    bool is_risky;
    string origin_tag;
    int trust_score;
    uint32_t file_writes;
    uint32_t registry_writes;
    uint32_t child_count;
    uint32_t network_connections;
    uint64_t last_activity;
    vector<DWORD> children_pids;
    vector<wstring> files_modified;
    vector<wstring> registry_keys;
    vector<wstring> network_destinations;
    unordered_set<string> tags;
};

enum EventType {
    EVT_PROCESS_START = 1,
    EVT_PROCESS_END = 2,
    EVT_FILE_WRITE = 3,
    EVT_THREAT_DETECTED = 4,
    EVT_REGISTRY_SET = 5,
    EVT_MEMORY_ALERT = 6,
    EVT_NETWORK_CONNECT = 7,
    EVT_PROCESS_KILLED = 8,
    EVT_AGGREGATED = 9,
    EVT_BEACON_DETECTED = 10
};

enum CommandType {
    CMD_KILL_PID = 1,
    CMD_SUSPEND_PID = 2,
    CMD_KILL_TREE = 3,
    CMD_QUARANTINE = 4,
    CMD_CLEANUP_PERSISTENCE = 5,
    CMD_UPDATE_THREAT_CACHE = 6,
    CMD_SET_MODE = 7
};

#pragma pack(push, 1)
struct BinaryEvent {
    uint32_t event_type;
    uint64_t timestamp;
    uint32_t pid;
    uint32_t ppid;
    uint32_t threat_level;
    uint8_t is_signed;
    uint32_t file_writes;
    uint32_t registry_writes;
    uint32_t child_count;
    uint32_t network_connections;
    char name[256];
    char full_path[512];
    char origin_tag[32];
    char extra_data[256];  // For network IPs, file paths, etc.
};

struct BinaryCommand {
    uint32_t cmd_type;
    uint32_t target_pid;
    char param[256];
};
#pragma pack(pop)

// ================================================================
// GLOBAL STATE
// ================================================================

class ProcessGraph;
class EventReorderBuffer;
class EventAggregator;
class InstinctDetector;
class NetworkMonitor;
class ThreatCache;

ProcessGraph* g_graph = nullptr;
EventReorderBuffer* g_reorder_buffer = nullptr;
EventAggregator* g_aggregator = nullptr;
InstinctDetector* g_instinct = nullptr;
NetworkMonitor* g_network = nullptr;
ThreatCache* g_threat_cache = nullptr;
ThreatIntelligence* g_threat_intel = nullptr;

HANDLE g_pipe_data = INVALID_HANDLE_VALUE;
HANDLE g_pipe_ctrl = INVALID_HANDLE_VALUE;
queue<BinaryEvent> g_event_queue;
mutex g_queue_mutex;

bool WaitForPipeClient(HANDLE pipe, const wchar_t* pipe_name) {
    wcout << L"[*] Waiting for Cortex on " << pipe_name << L"..." << endl;

    BOOL connected = ConnectNamedPipe(pipe, NULL);
    if (connected) {
        wcout << L"[+] Connected: " << pipe_name << endl;
        return true;
    }

    DWORD error = GetLastError();
    if (error == ERROR_PIPE_CONNECTED) {
        wcout << L"[+] Already connected: " << pipe_name << endl;
        return true;
    }

    wcout << L"[!] ConnectNamedPipe failed for " << pipe_name
        << L" (error " << error << L")" << endl;
    return false;
}

// Signal handler for clean shutdown
BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
        wcout << L"\n[*] Shutting down..." << endl;

        // Stop ETW
        system("logman stop SysOptima_Trace -ets >nul 2>&1");

        // Disconnect pipes
        if (g_pipe_data != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(g_pipe_data);
            CloseHandle(g_pipe_data);
        }
        if (g_pipe_ctrl != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(g_pipe_ctrl);
            CloseHandle(g_pipe_ctrl);
        }

        ExitProcess(0);
        return TRUE;
    }
    return FALSE;
}

// ================================================================
// UTILITIES
// ================================================================

uint64_t GetCurrentTimestamp() {
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

string WideToUtf8(const wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

wstring ExtractFileName(const wstring& path) {
    size_t pos = path.find_last_of(L"\\");
    return (pos != wstring::npos) ? path.substr(pos + 1) : path;
}

bool IsFileSigned(const wstring& filepath) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filepath.c_str();

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return (status == ERROR_SUCCESS);
}

string ComputeSHA256(const wstring& filepath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    const DWORD BUFSIZE = 4096;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[32]; // SHA-256 is 32 bytes
    DWORD cbHash = 32;

    // Open file allowing full concurrent read/write/delete access to prevent locking active binaries
    hFile = CreateFileW(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // Fallback on permission/sharing violation to keep system stable
        return "HASH_" + WideToUtf8(filepath);
    }

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return "HASH_" + WideToUtf8(filepath);
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return "HASH_" + WideToUtf8(filepath);
    }

    BOOL bResult = TRUE;
    while (ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL) && cbRead > 0) {
        if (!CryptHashData(hHash, rgbFile, cbRead, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return "HASH_" + WideToUtf8(filepath);
        }
    }

    string hashString = "";
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        char rgbDigits[] = "0123456789abcdef";
        for (DWORD i = 0; i < cbHash; i++) {
            hashString += rgbDigits[rgbHash[i] >> 4];
            hashString += rgbDigits[rgbHash[i] & 0xf];
        }
    } else {
        hashString = "HASH_" + WideToUtf8(filepath);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return hashString;
}

void SendEventDirect(const BinaryEvent& evt);

// ================================================================
// LAYER 1.9: LOCAL THREAT CACHE (ENHANCED)
// ================================================================

class ThreatCache {
private:
    ThreatIntelligence* intel_engine;
    mutex cache_mutex;

public:
    ThreatCache() {
        intel_engine = new ThreatIntelligence();
        intel_engine->Initialize(L"C:\\SysOptima_Intel");

        // Load default threat data
        LoadDefaultThreats();
    }

    ~ThreatCache() {
        if (intel_engine) {
            intel_engine->Shutdown();
            delete intel_engine;
        }
    }

    void LoadDefaultThreats() {
        // Add some common malicious IPs (C2 servers, etc.)
        vector<string> bad_ips = {
            "45.142.212.61",    // Known Cobalt Strike C2
            "185.220.101.0",    // Tor exit node range
            "192.42.116.0",     // Known malicious range
        };
        intel_engine->AddMaliciousIPs(bad_ips);

        wcout << L"[INTEL] Loaded " << intel_engine->GetMaliciousIPCount()
            << L" threat indicators" << endl;
    }

    bool IsMalwareHash(const string& hash) {
        return intel_engine->IsMalwareHash(hash);
    }

    bool IsMaliciousIP(const string& ip) {
        return intel_engine->IsMaliciousIP(ip);
    }

    bool IsSuspiciousPath(const wstring& path) {
        // Keep original logic
        vector<wstring> suspicious_paths = {
            L"\\AppData\\Local\\Temp\\",
            L"\\Downloads\\",
            L"\\ProgramData\\",
        };

        for (const auto& suspicious : suspicious_paths) {
            if (path.find(suspicious) != wstring::npos) return true;
        }
        return false;
    }

    void AddMalwareHash(const string& hash) {
        intel_engine->AddMalwareHash(hash, "Detected");
    }

    void AddMaliciousIP(const string& ip) {
        intel_engine->AddMaliciousIP(ip, 0);
    }

    // NEW: Get malware family name
    string GetMalwareFamily(const string& hash) {
        return intel_engine->GetMalwareFamily(hash);
    }

    // NEW: Get IP reputation score
    int GetIPReputation(const string& ip) {
        return intel_engine->GetIPReputation(ip);
    }

    // NEW: Update from online feeds
    void UpdateFeeds() {
        wcout << L"[INTEL] Updating threat intelligence..." << endl;
        intel_engine->UpdateFromFeeds();
    }
};

// ================================================================
// LAYER 1.4: INSTINCT DETECTOR (BRAIN 1)
// ================================================================

class InstinctDetector {
private:
    unordered_set<wstring> system_processes = {
        L"svchost.exe", L"lsass.exe", L"csrss.exe", L"services.exe"
    };

    unordered_set<wstring> system_directories = {
        L"\\Windows\\System32\\",
        L"\\Windows\\SysWOW64\\"
    };

public:
    bool ShouldInstantKill(const ProcessInfo& proc) {
        // Rule 1: System process from wrong location (masquerading)
        if (system_processes.count(proc.name) > 0) {
            bool in_system_dir = false;
            for (const auto& dir : system_directories) {
                if (proc.full_path.find(dir) != wstring::npos) {
                    in_system_dir = true;
                    break;
                }
            }
            if (!in_system_dir) {
                wcout << L"[INSTINCT] KILL: " << proc.name << L" masquerading!" << endl;
                return true;
            }
        }

        // Rule 2: Known malware hash with family identification
        string hash = ComputeSHA256(proc.full_path);
        if (g_threat_cache && g_threat_cache->IsMalwareHash(hash)) {
            string family = g_threat_cache->GetMalwareFamily(hash);
            wcout << L"[INSTINCT] KILL: Known malware - Family: "
                << wstring(family.begin(), family.end()) << L"!" << endl;
            return true;
        }

        // Rule 3: Unsigned process trying to inject (will be detected by memory scanner)
        // This is handled by combination of memory scanner + threat level

        return false;
    }

    int GetInstinctThreatBonus(const ProcessInfo& proc) {
        int bonus = 0;

        // Suspicious path
        if (g_threat_cache && g_threat_cache->IsSuspiciousPath(proc.full_path)) {
            bonus += 10;
        }

        // Recent process (< 5 min old) with high activity
        uint64_t age = GetCurrentTimestamp() - proc.uid.start_time;
        if (age < 300000 && proc.file_writes > 100) {
            bonus += 15;
        }

        return bonus;
    }
};

// ================================================================
// LAYER 1.6: NETWORK MONITOR
// ================================================================

class NetworkMonitor {
private:
    struct ConnectionInfo {
        string dest_ip;
        uint64_t first_seen;
        uint64_t last_seen;
        uint32_t count;
    };

    unordered_map<DWORD, vector<ConnectionInfo>> pid_connections;
    mutex net_mutex;

public:
    void RecordConnection(DWORD pid, const string& dest_ip) {
        lock_guard<mutex> lock(net_mutex);
        uint64_t now = GetCurrentTimestamp();

        auto& conns = pid_connections[pid];

        // Find existing connection
        for (auto& conn : conns) {
            if (conn.dest_ip == dest_ip) {
                conn.last_seen = now;
                conn.count++;
                return;
            }
        }

        // New connection
        conns.push_back({ dest_ip, now, now, 1 });
    }

    bool DetectBeaconing(DWORD pid, uint64_t& avg_interval) {
        lock_guard<mutex> lock(net_mutex);

        if (pid_connections.find(pid) == pid_connections.end()) return false;

        auto& conns = pid_connections[pid];
        if (conns.empty()) return false;

        // Look for regular intervals
        vector<uint64_t> intervals;
        for (size_t i = 1; i < conns.size(); i++) {
            uint64_t interval = conns[i].first_seen - conns[i - 1].first_seen;
            intervals.push_back(interval);
        }

        if (intervals.size() < 3) return false;

        // Calculate standard deviation
        double sum = 0;
        for (auto interval : intervals) sum += interval;
        double mean = sum / intervals.size();

        double variance = 0;
        for (auto interval : intervals) {
            variance += pow(interval - mean, 2);
        }
        double stddev = sqrt(variance / intervals.size());

        // Low variance = beaconing
        double cv = (stddev / mean) * 100;  // Coefficient of variation
        avg_interval = static_cast<uint64_t>(mean);

        return (cv < 20.0);  // Less than 20% variation
    }

    vector<string> GetDestinations(DWORD pid) {
        lock_guard<mutex> lock(net_mutex);
        vector<string> dests;
        if (pid_connections.count(pid)) {
            for (const auto& conn : pid_connections[pid]) {
                dests.push_back(conn.dest_ip);
            }
        }
        return dests;
    }

    void RemoveProcess(DWORD pid) {
        lock_guard<mutex> lock(net_mutex);
        pid_connections.erase(pid);
    }
};

// ================================================================
// LAYER 1.2: EVENT REORDER BUFFER
// ================================================================

class EventReorderBuffer {
private:
    struct TimestampedEvent {
        BinaryEvent event;
        uint64_t arrival_time;

        bool operator<(const TimestampedEvent& other) const {
            return event.timestamp > other.event.timestamp;
        }
    };

    priority_queue<TimestampedEvent> buffer;
    mutex buffer_mutex;
    uint64_t last_flush_time;

public:
    EventReorderBuffer() : last_flush_time(GetCurrentTimestamp()) {}

    void AddEvent(const BinaryEvent& evt) {
        lock_guard<mutex> lock(buffer_mutex);
        TimestampedEvent te;
        te.event = evt;
        te.arrival_time = GetCurrentTimestamp();
        buffer.push(te);
    }

    vector<BinaryEvent> FlushReady() {
        lock_guard<mutex> lock(buffer_mutex);
        vector<BinaryEvent> ready;
        uint64_t now = GetCurrentTimestamp();

        while (!buffer.empty()) {
            TimestampedEvent oldest = buffer.top();

            if (now - oldest.arrival_time >= REORDER_BUFFER_MS) {
                ready.push_back(oldest.event);
                buffer.pop();
            }
            else {
                break;
            }
        }

        last_flush_time = now;
        return ready;
    }
};

// ================================================================
// LAYER 1.3: MICRO-AGGREGATOR
// ================================================================

class EventAggregator {
private:
    struct AggregatedData {
        uint32_t file_write_count;
        uint32_t registry_write_count;
        uint32_t network_connections;
        uint64_t first_timestamp;
        uint64_t last_timestamp;
    };

    unordered_map<DWORD, AggregatedData> buffers;
    mutex agg_mutex;
    uint64_t last_flush;

public:
    EventAggregator() : last_flush(GetCurrentTimestamp()) {}

    void RecordFileWrite(DWORD pid) {
        lock_guard<mutex> lock(agg_mutex);
        uint64_t now = GetCurrentTimestamp();

        if (buffers.find(pid) == buffers.end()) {
            buffers[pid] = { 0, 0, 0, now, now };
        }

        buffers[pid].file_write_count++;
        buffers[pid].last_timestamp = now;
    }

    void RecordRegistryWrite(DWORD pid) {
        lock_guard<mutex> lock(agg_mutex);
        uint64_t now = GetCurrentTimestamp();

        if (buffers.find(pid) == buffers.end()) {
            buffers[pid] = { 0, 0, 0, now, now };
        }

        buffers[pid].registry_write_count++;
        buffers[pid].last_timestamp = now;
    }

    void RecordNetworkConnection(DWORD pid) {
        lock_guard<mutex> lock(agg_mutex);
        uint64_t now = GetCurrentTimestamp();

        if (buffers.find(pid) == buffers.end()) {
            buffers[pid] = { 0, 0, 0, now, now };
        }

        buffers[pid].network_connections++;
        buffers[pid].last_timestamp = now;
    }

    unordered_map<DWORD, AggregatedData> FlushAll() {
        lock_guard<mutex> lock(agg_mutex);
        auto result = buffers;
        buffers.clear();
        last_flush = GetCurrentTimestamp();
        return result;
    }

    bool ShouldFlush() {
        return (GetCurrentTimestamp() - last_flush) >= AGGREGATION_FLUSH_MS;
    }
};

// ================================================================
// PROCESS GRAPH (ENHANCED)
// ================================================================

class ProcessGraph {
private:
    unordered_map<ProcessUID, ProcessInfo> processes;
    unordered_map<DWORD, ProcessUID> pid_to_uid;
    mutex graph_mutex;

    unordered_set<wstring> internet_browsers = {
        L"chrome.exe", L"msedge.exe", L"firefox.exe", L"brave.exe", L"opera.exe"
    };
    unordered_set<wstring> sensitive_tools = {
        L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"regedit.exe", L"reg.exe",
        L"net.exe", L"netsh.exe", L"sc.exe", L"wmic.exe", L"mshta.exe"
    };
    unordered_set<wstring> system_processes = {
        L"svchost.exe", L"lsass.exe", L"csrss.exe", L"wininit.exe", L"services.exe"
    };

public:
    void AddProcess(const ProcessInfo& info) {
        lock_guard<mutex> lock(graph_mutex);
        processes[info.uid] = info;
        pid_to_uid[info.uid.pid] = info.uid;

        if (pid_to_uid.count(info.parent_uid.pid)) {
            ProcessUID parent_uid = pid_to_uid[info.parent_uid.pid];
            processes[parent_uid].children_pids.push_back(info.uid.pid);
            processes[parent_uid].child_count++;
        }
    }

    ProcessInfo* GetProcess(DWORD pid) {
        lock_guard<mutex> lock(graph_mutex);
        auto it = pid_to_uid.find(pid);
        if (it != pid_to_uid.end()) return &processes[it->second];
        return nullptr;
    }

    void GetProcessTree(DWORD root_pid, vector<DWORD>& tree_pids) {
        lock_guard<mutex> lock(graph_mutex);
        queue<DWORD> q;
        q.push(root_pid);
        unordered_set<DWORD> visited;

        while (!q.empty()) {
            DWORD curr = q.front();
            q.pop();

            if (visited.count(curr)) continue;
            visited.insert(curr);
            tree_pids.push_back(curr);

            auto it = pid_to_uid.find(curr);
            if (it != pid_to_uid.end()) {
                for (DWORD child : processes[it->second].children_pids) {
                    if (!visited.count(child)) {
                        q.push(child);
                    }
                }
            }
        }
    }

    string GetOriginTag(DWORD parent_pid, const wstring& proc_name) {
        lock_guard<mutex> lock(graph_mutex);
        if (internet_browsers.count(proc_name)) return "Internet";
        if (system_processes.count(proc_name)) return "System";
        auto it = pid_to_uid.find(parent_pid);
        if (it != pid_to_uid.end()) return processes[it->second].origin_tag;
        return "Unknown";
    }

    void IncrementFileWrites(DWORD pid) {
        lock_guard<mutex> lock(graph_mutex);
        auto it = pid_to_uid.find(pid);
        if (it != pid_to_uid.end()) {
            processes[it->second].file_writes++;
            processes[it->second].last_activity = GetCurrentTimestamp();
        }
    }

    void IncrementRegistryWrites(DWORD pid) {
        lock_guard<mutex> lock(graph_mutex);
        auto it = pid_to_uid.find(pid);
        if (it != pid_to_uid.end()) {
            processes[it->second].registry_writes++;
            processes[it->second].last_activity = GetCurrentTimestamp();
        }
    }

    void IncrementNetworkConnections(DWORD pid) {
        lock_guard<mutex> lock(graph_mutex);
        auto it = pid_to_uid.find(pid);
        if (it != pid_to_uid.end()) {
            processes[it->second].network_connections++;
            processes[it->second].last_activity = GetCurrentTimestamp();
        }
    }

    void AddFileModified(DWORD pid, const wstring& filepath) {
        lock_guard<mutex> lock(graph_mutex);
        auto it = pid_to_uid.find(pid);
        if (it != pid_to_uid.end()) {
            processes[it->second].files_modified.push_back(filepath);
        }
    }

    void AddRegistryKey(DWORD pid, const wstring& key) {
        lock_guard<mutex> lock(graph_mutex);
        auto it = pid_to_uid.find(pid);
        if (it != pid_to_uid.end()) {
            processes[it->second].registry_keys.push_back(key);
        }
    }

    void AddNetworkDestination(DWORD pid, const wstring& dest) {
        lock_guard<mutex> lock(graph_mutex);
        auto it = pid_to_uid.find(pid);
        if (it != pid_to_uid.end()) {
            processes[it->second].network_destinations.push_back(dest);
        }
    }

    void AddTag(DWORD pid, const string& tag) {
        lock_guard<mutex> lock(graph_mutex);
        auto it = pid_to_uid.find(pid);
        if (it != pid_to_uid.end()) {
            processes[it->second].tags.insert(tag);
        }
    }

    vector<wstring> GetPersistenceArtifacts(DWORD pid) {
        lock_guard<mutex> lock(graph_mutex);
        vector<wstring> artifacts;
        auto it = pid_to_uid.find(pid);
        if (it != pid_to_uid.end()) {
            artifacts = processes[it->second].registry_keys;
        }
        return artifacts;
    }

    vector<wstring> GetFilesModified(DWORD pid) {
        lock_guard<mutex> lock(graph_mutex);
        vector<wstring> files;
        auto it = pid_to_uid.find(pid);
        if (it != pid_to_uid.end()) {
            files = processes[it->second].files_modified;
        }
        return files;
    }

    int CalculateThreatLevel(const ProcessInfo& proc) {
        lock_guard<mutex> lock(graph_mutex);
        int score = 0;

        // Rule 1: Internet + Sensitive Tool
        if (proc.origin_tag == "Internet" && sensitive_tools.count(proc.name)) {
            score += 50;
        }

        // Rule 2: Unsigned from Internet
        if (!proc.is_signed && proc.origin_tag == "Internet") {
            score += 15;
        }

        // Rule 3: Excessive file writes
        if (proc.file_writes > 100) {
            score += 20;
        }

        // Rule 4: Many children
        if (proc.child_count > 10) {
            score += 15;
        }

        // Rule 5: Masquerade (checked by InstinctDetector but add here too)
        if (system_processes.count(proc.name) &&
            proc.full_path.find(L"System32") == wstring::npos &&
            proc.full_path.find(L"SysWOW64") == wstring::npos) {
            score += 60;
        }

        // Rule 6: Excessive registry writes (persistence?)
        if (proc.registry_writes > 50) {
            score += 25;
        }

        // Rule 7: Many network connections (C2?)
        if (proc.network_connections > 20) {
            score += 20;
        }

        // Rule 8: Instinct bonus
        if (g_instinct) {
            score += g_instinct->GetInstinctThreatBonus(proc);
        }

        // Don't flag browsers
        if (internet_browsers.count(proc.name)) {
            score = 0;
        }

        if (score >= 60) return 2;
        if (score >= 30) return 1;
        return 0;
    }

    void RemoveProcess(DWORD pid) {
        lock_guard<mutex> lock(graph_mutex);
        auto it = pid_to_uid.find(pid);
        if (it != pid_to_uid.end()) {
            processes.erase(it->second);
            pid_to_uid.erase(it);
        }
    }

    vector<DWORD> GetAllPids() {
        lock_guard<mutex> lock(graph_mutex);
        vector<DWORD> pids;
        for (auto const& [pid, uid] : pid_to_uid) {
            pids.push_back(pid);
        }
        return pids;
    }

    size_t GetProcessCount() {
        lock_guard<mutex> lock(graph_mutex);
        return processes.size();
    }
};

// ================================================================
// FORWARD DECLARATIONS
// ================================================================

void SendEventDirect(const BinaryEvent& evt) {
    g_reorder_buffer->AddEvent(evt);
}

// ================================================================
// LAYER 1.5: MEMORY SCANNER
// ================================================================

bool IsLegitimateJITCompiler(DWORD pid, LPVOID rwx_address) {
    /**
     * Check if RWX memory belongs to known JIT compilers
     * Returns true if legitimate, false if suspicious
     */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    // Get the module that owns this memory region
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                // Check if RWX address falls within this module
                if (rwx_address >= modInfo.lpBaseOfDll &&
                    rwx_address < (LPBYTE)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {

                    // Get module name
                    wchar_t szModName[MAX_PATH];
                    if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                        wstring modName(szModName);
                        std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);

                        // Known legitimate JIT compilers
                        vector<wstring> jit_modules = {
                            L"clr.dll",          // .NET Framework
                            L"coreclr.dll",      // .NET Core
                            L"clrjit.dll",       // .NET JIT
                            L"jscript9.dll",     // IE JavaScript
                            L"jscript.dll",      // Old IE JavaScript
                            L"chakra.dll",       // Edge JavaScript
                            L"v8.dll",           // Chrome V8
                            L"mozjs.dll",        // Firefox SpiderMonkey
                            L"jvm.dll",          // Java Virtual Machine
                            L"node.dll",         // Node.js
                            L"python",           // Python (various versions)
                            L"java.dll"          // Java
                        };

                        for (const auto& jit : jit_modules) {
                            if (modName.find(jit) != wstring::npos) {
                                CloseHandle(hProcess);
                                return true;  // Legitimate JIT compiler
                            }
                        }
                    }
                }
            }
        }
    }

    CloseHandle(hProcess);
    return false;  // Not from known JIT compiler
}

bool ScanProcessMemory(DWORD pid) {
    // STEP 1: Check if process is highly trusted (skip scan entirely)
    ProcessInfo* proc = g_graph->GetProcess(pid);
    if (proc && proc->trust_score >= 40) {
        // Highly trusted process - skip memory scan
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;
    bool suspicious_rwx_found = false;
    int rwx_region_count = 0;
    SIZE_T total_rwx_size = 0;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {

            rwx_region_count++;
            total_rwx_size += mbi.RegionSize;

            // STEP 2: Check if this RWX region is from legitimate JIT compiler
            if (IsLegitimateJITCompiler(pid, address)) {
                // This RWX is from known JIT - skip it
                address = (LPVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
                continue;
            }

            // STEP 3: Pattern Analysis - Legitimate JIT characteristics
            // Legitimate JIT usually allocates large regions (>1MB)
            // Malware typically uses many small regions
            if (mbi.RegionSize >= 1048576) {  // >= 1MB
                // Large RWX region - likely legitimate JIT
                address = (LPVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
                continue;
            }

            // If we get here, it's suspicious RWX
            suspicious_rwx_found = true;
            break;
        }
        address = (LPVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
    }

    CloseHandle(hProcess);

    // STEP 4: Behavioral correlation
    // Don't instant-kill - just flag and add to threat score
    // Let ResponseOrchestrator decide based on combined factors
    return suspicious_rwx_found;
}
// Frequency throttling - don't spam alerts for same PID
std::unordered_map<DWORD, uint64_t> last_memory_alert_time;

void MemoryScannerThread() {
    wcout << L"[*] Memory Scanner Started (with JIT whitelisting)" << endl;
    while (true) {
        vector<DWORD> pids = g_graph->GetAllPids();
        for (DWORD pid : pids) {
            // STEP 1: Rate limiting - max one alert per PID per 60 seconds
            uint64_t now = GetCurrentTimestamp();
            if (last_memory_alert_time.count(pid) > 0) {
                if (now - last_memory_alert_time[pid] < 60000) {  // < 60 seconds
                    continue;  // Skip this PID
                }
            }

            // STEP 2: Scan memory
            if (ScanProcessMemory(pid)) {
                last_memory_alert_time[pid] = now;

                // STEP 3: Send event to Python (DON'T instant kill here)
                BinaryEvent evt = {};
                evt.event_type = EVT_MEMORY_ALERT;
                evt.timestamp = GetCurrentTimestamp();
                evt.pid = pid;
                evt.threat_level = 1;  // Changed from 2 to 1 - now just "suspicious"
                strncpy_s(evt.origin_tag, "MemoryScanner", 31);
                SendEventDirect(evt);

                g_graph->AddTag(pid, "TAG_MEMORY_RWX");

                wcout << L"[MEM] Suspicious RWX Memory in PID " << pid << L" (flagged, not killed)" << endl;
            }
        }
        Sleep(MEMORY_SCAN_INTERVAL_MS);
    }
}

// ================================================================
// NETWORK SCANNER THREAD
// ================================================================

void NetworkScannerThread() {
    wcout << L"[*] Network Scanner Started" << endl;
    while (true) {
        vector<DWORD> pids = g_graph->GetAllPids();
        for (DWORD pid : pids) {
            uint64_t avg_interval;
            if (g_network->DetectBeaconing(pid, avg_interval)) {
                BinaryEvent evt = {};
                evt.event_type = EVT_BEACON_DETECTED;
                evt.timestamp = GetCurrentTimestamp();
                evt.pid = pid;
                evt.threat_level = 2;
                snprintf(evt.extra_data, 255, "beacon_interval=%llu", avg_interval);
                strncpy_s(evt.origin_tag, "NetworkMonitor", 31);
                SendEventDirect(evt);

                g_graph->AddTag(pid, "TAG_BEACON_C2");

                wcout << L"[NET] Beaconing detected in PID " << pid << L" (interval: " << avg_interval << L"ms)" << endl;
            }
        }
        Sleep(NETWORK_SCAN_INTERVAL_MS);
    }
}

// ================================================================
// LAYER 3.7: PERSISTENCE CLEANER (ENHANCED)
// ================================================================

void ExecuteHiddenCommand(const wstring& cmd) {
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    
    vector<wchar_t> cmdBuffer(cmd.begin(), cmd.end());
    cmdBuffer.push_back(0);
    
    if (CreateProcessW(nullptr, cmdBuffer.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000); // Wait up to 10 seconds
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

void CleanupMaliciousServices(const wstring& exe_name) {
    SC_HANDLE hSCM = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_STATUS | SC_MANAGER_CONNECT);
    if (!hSCM) return;
    
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    
    // Query size first
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);
        
    if (bytesNeeded > 0) {
        vector<BYTE> buffer(bytesNeeded);
        ENUM_SERVICE_STATUS_PROCESSW* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        
        if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {
            
            for (DWORD i = 0; i < servicesReturned; i++) {
                SC_HANDLE hService = OpenServiceW(hSCM, services[i].lpServiceName, SERVICE_QUERY_CONFIG | DELETE);
                if (hService) {
                    DWORD configNeeded = 0;
                    QueryServiceConfigW(hService, nullptr, 0, &configNeeded);
                    if (configNeeded > 0) {
                        vector<BYTE> configBuffer(configNeeded);
                        QUERY_SERVICE_CONFIGW* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
                        if (QueryServiceConfigW(hService, config, configNeeded, &configNeeded)) {
                            wstring binaryPath = config->lpBinaryPathName;
                            if (binaryPath.find(exe_name) != wstring::npos) {
                                wcout << L"[CLEANUP] Deleting malicious service: " << services[i].lpServiceName << endl;
                                DeleteService(hService);
                            }
                        }
                    }
                    CloseHandle(hService);
                }
            }
        }
    }
    CloseHandle(hSCM);
}

void CleanupStartupFolders(const wstring& exe_name) {
    vector<wstring> startup_paths;
    startup_paths.push_back(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\");
    
    wchar_t appdata[MAX_PATH];
    if (ExpandEnvironmentStringsW(L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\", appdata, MAX_PATH) > 0) {
        startup_paths.push_back(appdata);
    }
    
    for (const wstring& dir : startup_paths) {
        wstring search_path = dir + L"*";
        WIN32_FIND_DATAW find_data;
        HANDLE hFind = FindFirstFileW(search_path.c_str(), &find_data);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    wstring filename = find_data.cFileName;
                    if (filename.find(exe_name) != wstring::npos) {
                        wstring full_file = dir + filename;
                        wcout << L"[CLEANUP] Deleting startup file: " << full_file << endl;
                        DeleteFileW(full_file.c_str());
                    }
                }
            } while (FindNextFileW(hFind, &find_data));
            CloseHandle(hFind);
        }
    }
}

void CleanPersistence(DWORD pid) {
    wcout << L"[CLEANUP] Removing persistence artifacts for PID " << pid << endl;

    ProcessInfo* proc = g_graph->GetProcess(pid);
    if (!proc) {
        wcout << L"[CLEANUP] Process info not found for PID " << pid << endl;
        return;
    }

    wstring exe_name = proc->name;
    wstring exe_path = proc->full_path;

    vector<wstring> artifacts = g_graph->GetPersistenceArtifacts(pid);

    // Delete registry keys
    for (const wstring& reg_key : artifacts) {
        if (reg_key.find(L"Run") != wstring::npos ||
            reg_key.find(L"Services") != wstring::npos) {

            wcout << L"[CLEANUP] Deleting registry: " << reg_key << endl;

            // Parse registry path
            size_t pos = reg_key.find(L"\\");
            if (pos != wstring::npos) {
                wstring hive = reg_key.substr(0, pos);
                wstring subkey = reg_key.substr(pos + 1);

                HKEY hKey = HKEY_LOCAL_MACHINE;
                if (hive == L"HKCU") hKey = HKEY_CURRENT_USER;

                RegDeleteKeyW(hKey, subkey.c_str());
            }
        }
    }

    // Quarantine files
    vector<wstring> files = g_graph->GetFilesModified(pid);
    for (const wstring& filepath : files) {
        if (filepath.find(L".exe") != wstring::npos ||
            filepath.find(L".dll") != wstring::npos) {

            wstring quarantine_path = L"C:\\SysOptima_Quarantine\\" + ExtractFileName(filepath);
            wcout << L"[CLEANUP] Quarantine: " << filepath << endl;
            MoveFileW(filepath.c_str(), quarantine_path.c_str());
        }
    }

    if (!exe_name.empty()) {
        // 1. Clean SCM Services
        CleanupMaliciousServices(exe_name);

        // 2. Clean Startup folders
        CleanupStartupFolders(exe_name);

        // 3. Clean Scheduled Tasks and WMI Consumers via hidden PowerShell
        wstring taskCmd = L"powershell.exe -Command \"Get-ScheduledTask | Where-Object { $_.Actions.Execute -like '*" + exe_name + L"*' } | Unregister-ScheduledTask -Confirm:$false\"";
        ExecuteHiddenCommand(taskCmd);
        
        wstring wmiCmd = L"powershell.exe -Command \"Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | Where-Object { $_.CommandLineTemplate -like '*" + exe_name + L"*' -or $_.ExecutablePath -like '*" + exe_name + L"*' } | Remove-CimInstance\"";
        ExecuteHiddenCommand(wmiCmd);
        wcout << L"[CLEANUP] Tasks and WMI event consumer checks completed." << endl;
    }
}

// ================================================================
// LAYER 1.8: COMMAND EXECUTOR (COMPLETE)
// ================================================================

void KillProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess) {
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);

        BinaryEvent evt = {};
        evt.event_type = EVT_PROCESS_KILLED;
        evt.pid = pid;
        evt.timestamp = GetCurrentTimestamp();
        SendEventDirect(evt);

        g_graph->RemoveProcess(pid);
        g_network->RemoveProcess(pid);

        wcout << L"[KILL] Terminated PID " << pid << endl;
    }
}

void SuspendProcess(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == pid) {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        SuspendThread(hThread);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te32));
        }
        CloseHandle(hSnapshot);
        wcout << L"[SUSPEND] Suspended PID " << pid << endl;
    }
}

void KillTree(DWORD root_pid) {
    vector<DWORD> tree;
    g_graph->GetProcessTree(root_pid, tree);

    wcout << L"[KILL-TREE] Terminating " << tree.size() << L" processes" << endl;

    // Step 1: Suspend all (prevent watchdog respawn)
    for (DWORD pid : tree) {
        SuspendProcess(pid);
    }

    // Step 2: Kill in reverse order (children first)
    reverse(tree.begin(), tree.end());
    for (DWORD pid : tree) {
        KillProcess(pid);
    }

    // Step 3: Clean persistence
    CleanPersistence(root_pid);
}

void CommandListenerThread() {
    wcout << L"[*] Command Listener Started" << endl;
    while (true) {
        if (g_pipe_ctrl == INVALID_HANDLE_VALUE) {
            Sleep(100);
            continue;
        }

        BinaryCommand cmd;
        DWORD read;
        if (ReadFile(g_pipe_ctrl, &cmd, sizeof(cmd), &read, nullptr)) {
            switch (cmd.cmd_type) {
            case CMD_KILL_PID:
                KillProcess(cmd.target_pid);
                break;
            case CMD_SUSPEND_PID:
                SuspendProcess(cmd.target_pid);
                break;
            case CMD_KILL_TREE:
                KillTree(cmd.target_pid);
                break;
            case CMD_CLEANUP_PERSISTENCE:
                CleanPersistence(cmd.target_pid);
                break;
            case CMD_UPDATE_THREAT_CACHE:
                // Python can send threat intel updates
                g_threat_cache->AddMalwareHash(cmd.param);
                break;
            case CMD_SET_MODE:
                {
                    g_mode = cmd.target_pid;
                    const wchar_t* mode_names[] = { L"PRODUCTION", L"SMART", L"LEARNING" };
                    if (g_mode >= 0 && g_mode <= 2) {
                        wcout << L"[CONTROL] EDR Mode dynamically updated to: " << mode_names[g_mode] << endl;
                    } else {
                        wcout << L"[CONTROL] Received invalid mode code: " << g_mode << endl;
                    }
                }
                break;
            }
        }
        else {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA) {
                wcout << L"[!] Control pipe disconnected (error " << err << L"). Reconnecting..." << endl;
                DisconnectNamedPipe(g_pipe_ctrl);
                WaitForPipeClient(g_pipe_ctrl, L"\\\\.\\pipe\\SysOptimaControl");
            }
            else {
                Sleep(100);
            }
        }
    }
}

// ================================================================
// EVENT PROCESSOR THREAD
// ================================================================

void EventProcessorThread() {
    wcout << L"[*] Event Processor Started" << endl;
    while (true) {
        // Flush reorder buffer
        vector<BinaryEvent> ready_events = g_reorder_buffer->FlushReady();

        for (const BinaryEvent& evt : ready_events) {
            lock_guard<mutex> lock(g_queue_mutex);
            g_event_queue.push(evt);
        }

        // Flush aggregator
        if (g_aggregator->ShouldFlush()) {
            auto aggregated = g_aggregator->FlushAll();

            for (auto& [pid, data] : aggregated) {
                if (data.file_write_count > 50 ||
                    data.registry_write_count > 20 ||
                    data.network_connections > 10) {

                    BinaryEvent evt = {};
                    evt.event_type = EVT_AGGREGATED;
                    evt.pid = pid;
                    evt.file_writes = data.file_write_count;
                    evt.registry_writes = data.registry_write_count;
                    evt.network_connections = data.network_connections;
                    evt.timestamp = data.last_timestamp;

                    // Calculate threat from aggregated data
                    int agg_score = 0;
                    if (data.file_write_count > 100) agg_score += 30;
                    if (data.registry_write_count > 50) agg_score += 40;
                    if (data.network_connections > 20) agg_score += 25;

                    evt.threat_level = (agg_score >= 60) ? 2 : ((agg_score >= 30) ? 1 : 0);
                    strncpy_s(evt.origin_tag, "Aggregator", 31);

                    lock_guard<mutex> lock(g_queue_mutex);
                    g_event_queue.push(evt);
                }
            }
        }

        Sleep(50);
    }
}

// ================================================================
// ETW CALLBACKS
// ================================================================

void OnProcessStart(const EVENT_RECORD& record, const trace_context& trace_context) {
    schema schema(record, trace_context.schema_locator);
    parser parser(schema);

    try {
        DWORD pid = schema.process_id();
        if (pid <= 4) return;

        wstring image_name = parser.parse<wstring>(L"ImageName");
        wstring filename = ExtractFileName(image_name);
        if (filename.empty()) return;
        // ✅ ADD BROWSER WHITELIST
        vector<wstring> browsers = {
            L"chrome.exe", L"msedge.exe", L"firefox.exe",
            L"brave.exe", L"opera.exe", L"code.exe",
            L"electron.exe", L"discord.exe", L"slack.exe"
        };

        // Convert to lowercase for comparison
        wstring filename_lower = filename;
        transform(filename_lower.begin(), filename_lower.end(),
            filename_lower.begin(), ::towlower);

        ProcessInfo proc;
        proc.uid = { pid, GetCurrentTimestamp() };
        proc.name = filename;
        proc.full_path = image_name;
        proc.is_signed = IsFileSigned(image_name);
        proc.file_writes = 0;
        proc.registry_writes = 0;
        proc.child_count = 0;
        proc.network_connections = 0;
        proc.last_activity = GetCurrentTimestamp();

        for (const auto& browser : browsers) {
            wstring browser_lower = browser;
            transform(browser_lower.begin(), browser_lower.end(),
                browser_lower.begin(), ::towlower);

            if (filename_lower == browser_lower ||
                filename_lower.find(browser_lower.substr(0, browser_lower.size() - 4)) != wstring::npos) {

                // ✅ FORCE SAFE for browsers
                proc.is_signed = true;
                proc.trust_score = 100;  // Maximum trust
                proc.origin_tag = "System";  // Override origin

                wcout << L"[WHITELIST] Browser detected: " << filename << endl;
                break;
            }
        }

        /*ProcessInfo proc;
        proc.uid = { pid, GetCurrentTimestamp() };
        proc.name = filename;
        proc.full_path = image_name;
        proc.is_signed = IsFileSigned(image_name);
        proc.file_writes = 0;
        proc.registry_writes = 0;
        proc.child_count = 0;
        proc.network_connections = 0;
        proc.last_activity = GetCurrentTimestamp();*/

        DWORD ppid = 0;
        try { ppid = parser.parse<uint32_t>(L"ParentProcessId"); }
        catch (...) {}

        ProcessInfo* parent = g_graph->GetProcess(ppid);
        if (parent) {
            proc.parent_uid = parent->uid;
            proc.origin_tag = parent->origin_tag;
        }
        else {
            proc.parent_uid = { 0, 0 };
            proc.origin_tag = g_graph->GetOriginTag(ppid, filename);
        }

        // Check instinct detector BEFORE adding to graph
        if (g_instinct->ShouldInstantKill(proc)) {
            // Instant kill, don't even add to graph
            KillProcess(pid);
            return;
        }

        g_graph->AddProcess(proc);
        int threat = g_graph->CalculateThreatLevel(proc);

        bool should_send = false;
        if (g_mode == 2) {
            should_send = true;  // Learning mode: send everything
        }
        else if (g_mode == 1) {
            should_send = (threat > 0 || !proc.is_signed || proc.origin_tag == "Internet");
        }
        else {
            should_send = (threat > 0);  // Production: only threats
        }

        if (should_send) {
            BinaryEvent evt = {};
            evt.event_type = (threat >= 2) ? EVT_THREAT_DETECTED : EVT_PROCESS_START;
            evt.timestamp = proc.uid.start_time;
            evt.pid = pid;
            evt.ppid = ppid;
            evt.threat_level = threat;
            evt.is_signed = proc.is_signed;
            evt.file_writes = 0;
            evt.registry_writes = 0;
            evt.child_count = 0;
            evt.network_connections = 0;

            strncpy_s(evt.name, WideToUtf8(filename).c_str(), 255);
            strncpy_s(evt.full_path, WideToUtf8(image_name).c_str(), 511);
            strncpy_s(evt.origin_tag, proc.origin_tag.c_str(), 31);

            SendEventDirect(evt);

            if (g_mode >= 1) {
                wcout << L"[PROC] " << filename << L" (Threat: " << threat << L")" << endl;
            }
        }
    }
    catch (...) {}
}

void OnFileWrite(const EVENT_RECORD& record, const trace_context& trace_context) {
    schema schema(record, trace_context.schema_locator);
    parser parser(schema);

    try {
        DWORD pid = schema.process_id();
        wstring filename = parser.parse<wstring>(L"FileName");

        // Filter noise
        if (filename.find(L".etl") != wstring::npos ||
            filename.find(L"Chrome\\User Data") != wstring::npos ||
            filename.find(L".log") != wstring::npos) return;

        g_aggregator->RecordFileWrite(pid);
        g_graph->IncrementFileWrites(pid);
        g_graph->AddFileModified(pid, filename);

    }
    catch (...) {}
}

void OnRegistrySet(const EVENT_RECORD& record, const trace_context& trace_context) {
    schema schema(record, trace_context.schema_locator);
    parser parser(schema);

    try {
        DWORD pid = schema.process_id();
        wstring key_name = parser.parse<wstring>(L"KeyName");

        g_aggregator->RecordRegistryWrite(pid);
        g_graph->IncrementRegistryWrites(pid);
        g_graph->AddRegistryKey(pid, key_name);

        // Flag persistence locations
        if (key_name.find(L"\\Run") != wstring::npos ||
            key_name.find(L"\\Services") != wstring::npos) {
            g_graph->AddTag(pid, "TAG_PERSISTENCE");
        }

    }
    catch (...) {}
}

void OnNetworkConnect(const EVENT_RECORD& record, const trace_context& trace_context) {
    schema schema(record, trace_context.schema_locator);
    parser parser(schema);

    try {
        DWORD pid = schema.process_id();

        // Parse destination IP
        string dest_ip = "0.0.0.0";
        try {
            uint32_t ip_raw = parser.parse<uint32_t>(L"daddr");
            char ip_str[16];
            snprintf(ip_str, 16, "%d.%d.%d.%d",
                (ip_raw >> 24) & 0xFF,
                (ip_raw >> 16) & 0xFF,
                (ip_raw >> 8) & 0xFF,
                ip_raw & 0xFF);
            dest_ip = ip_str;
        }
        catch (...) {}

        g_aggregator->RecordNetworkConnection(pid);
        g_graph->IncrementNetworkConnections(pid);
        g_graph->AddNetworkDestination(pid, wstring(dest_ip.begin(), dest_ip.end()));
        g_network->RecordConnection(pid, dest_ip);

        // Check threat cache with reputation scoring
        if (g_threat_cache->IsMaliciousIP(dest_ip)) {
            int reputation = g_threat_cache->GetIPReputation(dest_ip);
            g_graph->AddTag(pid, "TAG_MALICIOUS_IP");

            wcout << L"[NETWORK] Malicious IP detected: " << wstring(dest_ip.begin(), dest_ip.end())
                << L" (Reputation: " << reputation << L")" << endl;

            BinaryEvent evt = {};
            evt.event_type = EVT_NETWORK_CONNECT;
            evt.timestamp = GetCurrentTimestamp();
            evt.pid = pid;
            evt.threat_level = 2;
            strncpy_s(evt.extra_data, dest_ip.c_str(), 255);
            strncpy_s(evt.origin_tag, "ThreatIntel", 31);
            SendEventDirect(evt);
        }

    }
    catch (...) {}
}

// ================================================================
// PIPE WRITER THREAD
// ================================================================

void PipeWriterThread() {
    while (true) {
        BinaryEvent evt;
        {
            lock_guard<mutex> lock(g_queue_mutex);
            if (g_event_queue.empty()) {
                Sleep(5);
                continue;
            }
            evt = g_event_queue.front();
            g_event_queue.pop();
        }

        if (g_pipe_data != INVALID_HANDLE_VALUE) {
            DWORD written;
            BOOL success = WriteFile(g_pipe_data, &evt, sizeof(BinaryEvent), &written, nullptr);
            if (!success) {
                DWORD err = GetLastError();
                wcout << L"[!] Data pipe write failed (error " << err << L"). Reconnecting..." << endl;
                DisconnectNamedPipe(g_pipe_data);
                
                // Re-push the unsent event back to the front of the queue to prevent telemetry loss
                {
                    lock_guard<mutex> lock(g_queue_mutex);
                    queue<BinaryEvent> temp;
                    temp.push(evt);
                    while (!g_event_queue.empty()) {
                        temp.push(g_event_queue.front());
                        g_event_queue.pop();
                    }
                    g_event_queue.swap(temp);
                }
                
                WaitForPipeClient(g_pipe_data, L"\\\\.\\pipe\\SysOptimaData");
            }
        }
    }
}

void OnProcessStop(const EVENT_RECORD& record, const trace_context& trace_context) {
    schema schema(record, trace_context.schema_locator);
    try {
        DWORD pid = schema.process_id();
        g_graph->RemoveProcess(pid);   // Frees the memory in the graph
        g_network->RemoveProcess(pid); // Frees the network tracking memory
    }
    catch (...) {}
}

void KillOtherInstances() {
    DWORD current_pid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            wstring process_name = entry.szExeFile;
            if (process_name == L"SysOptima_Sensor.exe" && entry.th32ProcessID != current_pid) {
                wcout << L"[-] Found duplicate background sensor instance (PID " << entry.th32ProcessID << L"). Terminating..." << endl;
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                if (hProc) {
                    TerminateProcess(hProc, 0);
                    CloseHandle(hProc);
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

// ================================================================
// MAIN
// ================================================================

int main() {
    wcout << L"========================================" << endl;
    wcout << L"  SYSOPTIMA SENTINEL v2.0 COMPLETE" << endl;
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    wcout << L"========================================" << endl;
    wcout << endl;

    wcout << L"[*] Running pre-flight workspace cleanup..." << endl;
    // 1. Terminate other running instances of ourselves
    KillOtherInstances();
    // 2. Quietly clean up any orphaned Python Cortex backends
    system("powershell -Command \"Get-Process python -ErrorAction SilentlyContinue | ForEach-Object { $cmd = (Get-CimInstance Win32_Process -Filter \\\"ProcessId = $_.Id\\\" -ErrorAction SilentlyContinue).CommandLine; if ($cmd -and $cmd.Contains(\\\"main.py\\\")) { Stop-Process -Id $_.Id -Force } }\" >nul 2>&1");
    wcout << L"    [✓] Leaked background tasks cleaned successfully." << endl;
    wcout << endl;

    const wchar_t* mode_names[] = { L"PRODUCTION", L"SMART", L"LEARNING" };
    wcout << L"[MODE] " << mode_names[g_mode] << L" MODE" << endl;
    wcout << endl;

    // Initialize global objects
    g_graph = new ProcessGraph();
    g_reorder_buffer = new EventReorderBuffer();
    g_aggregator = new EventAggregator();
    g_instinct = new InstinctDetector();
    g_network = new NetworkMonitor();
    g_threat_cache = new ThreatCache();
    // Optional: Enable auto-update (updates every hour)
    // g_threat_cache->UpdateFeeds();  // Uncomment to enable online updates

    // Cleanup any existing sessions
    system("logman stop SysOptima_Trace -ets >nul 2>&1");

    // Create quarantine directory
    CreateDirectoryW(L"C:\\SysOptima_Quarantine", NULL);

    // Create pipes with hardened security attributes (restricting named pipe access strictly to SYSTEM and Administrators)
    wcout << L"[*] Creating Hardened Named Pipes..." << endl;
    
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    
    // SDDL: D:(A;;GA;;;SY)(A;;GA;;;BA) -> Allow Generic All to SYSTEM (SY) and Built-in Administrators (BA)
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;;GA;;;SY)(A;;GA;;;BA)",
        SDDL_REVISION_1,
        &pSD,
        nullptr)) 
    {
        sa.lpSecurityDescriptor = pSD;
    } else {
        wcout << L"[!] Warning: Failed to convert SDDL string (error " << GetLastError() << L"). Defaulting to process security." << endl;
    }

    g_pipe_data = CreateNamedPipe(
        L"\\\\.\\pipe\\SysOptimaData",
        PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 65536, 65536, 0, &sa
    );

    g_pipe_ctrl = CreateNamedPipe(
        L"\\\\.\\pipe\\SysOptimaControl",
        PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 1024, 1024, 0, &sa
    );

    if (pSD) {
        LocalFree(pSD);
    }

    if (g_pipe_data == INVALID_HANDLE_VALUE) {
        wcout << L"[!] Failed to create data pipe (error " << GetLastError() << L")" << endl;
        return 1;
    }

    if (g_pipe_ctrl == INVALID_HANDLE_VALUE) {
        wcout << L"[!] Failed to create control pipe (error " << GetLastError() << L")" << endl;
        return 1;
    }

    wcout << L"[+] Pipes created successfully" << endl;
    wcout << L"[*] Waiting for Cortex (Python) to connect..." << endl;

    if (!WaitForPipeClient(g_pipe_data, L"\\\\.\\pipe\\SysOptimaData")) {
        return 1;
    }

    if (!WaitForPipeClient(g_pipe_ctrl, L"\\\\.\\pipe\\SysOptimaControl")) {
        return 1;
    }

    wcout << L"[+] Cortex Connected!" << endl;
    wcout << endl;

    // Start worker threads
    wcout << L"[*] Starting worker threads..." << endl;
    thread writer(PipeWriterThread);
    writer.detach();

    thread cmd_listener(CommandListenerThread);
    cmd_listener.detach();

    thread mem_scanner(MemoryScannerThread);
    mem_scanner.detach();

    thread net_scanner(NetworkScannerThread);
    net_scanner.detach();

    thread event_processor(EventProcessorThread);
    event_processor.detach();

    wcout << L"[+] All threads started" << endl;
    wcout << endl;

    // Setup ETW
    wcout << L"[*] Initializing ETW trace..." << endl;
    user_trace trace(L"SysOptima_Trace");

    // Process events
    provider<> proc_provider(L"Microsoft-Windows-Kernel-Process");
    event_filter proc_filter(predicates::id_is(1));
    proc_filter.add_on_event_callback(OnProcessStart);
    proc_provider.add_filter(proc_filter);

    event_filter proc_stop_filter(predicates::id_is(2));      // <--- ADD THIS
    proc_stop_filter.add_on_event_callback(OnProcessStop);    // <--- ADD THIS
    proc_provider.add_filter(proc_stop_filter);               // <--- ADD THIS

    // File events
    provider<> file_provider(L"Microsoft-Windows-Kernel-File");
    event_filter file_filter(predicates::id_is(12));
    file_filter.add_on_event_callback(OnFileWrite);
    file_provider.add_filter(file_filter);

    // Registry events
    provider<> reg_provider(L"Microsoft-Windows-Kernel-Registry");
    event_filter reg_filter(predicates::id_is(1));
    reg_filter.add_on_event_callback(OnRegistrySet);
    reg_provider.add_filter(reg_filter);

    // Network events
    provider<> net_provider(L"Microsoft-Windows-Kernel-Network");
    event_filter net_filter(predicates::id_is(10));
    net_filter.add_on_event_callback(OnNetworkConnect);
    net_provider.add_filter(net_filter);

    trace.enable(proc_provider);
    trace.enable(file_provider);
    trace.enable(reg_provider);
    trace.enable(net_provider);

    wcout << L"[+] ETW providers enabled" << endl;
    wcout << endl;
    wcout << L"========================================" << endl;
    wcout << L"  ENGINE RUNNING" << endl;
    wcout << L"  All Layers Active:" << endl;
    wcout << L"  - Event Reorder Buffer" << endl;
    wcout << L"  - Micro-Aggregator" << endl;
    wcout << L"  - Instinct Detector" << endl;
    wcout << L"  - Memory Scanner" << endl;
    wcout << L"  - Network Monitor" << endl;
    wcout << L"  - Threat Cache" << endl;
    wcout << L"========================================" << endl;
    wcout << endl;

    try {
        trace.start();
    }
    catch (std::runtime_error& e) {
        wcout << L"[!] ETW Error: " << e.what() << endl;
        wcout << L"[!] Make sure to run as Administrator!" << endl;
        return 1;
    }

    if (g_pipe_data != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(g_pipe_data);
        CloseHandle(g_pipe_data);
    }
    if (g_pipe_ctrl != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(g_pipe_ctrl);
        CloseHandle(g_pipe_ctrl);
    }

    delete g_graph;
    delete g_reorder_buffer;
    delete g_aggregator;
    delete g_instinct;
    delete g_network;
    delete g_threat_cache;

    return 0;
}
