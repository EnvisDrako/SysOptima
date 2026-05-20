// ================================================================
// THREAT INTELLIGENCE MODULEE
// Real-time threat feeds, hash/IP lookups, reputation scoring
// ================================================================
#pragma once

#ifndef WINVER
#define WINVER 0x0A00
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

// Windows headers MUST come first and in this order
#include <windows.h>       // MUST be first - For Windows API, CreateDirectoryW
#include <wininet.h>       // MUST be after windows.h - For Internet functions

// Standard C++ headers
#include <iostream>        // For wcout, endl
#include <chrono>          // For duration_cast, system_clock
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <fstream>
#include <sstream>
#include <algorithm>       // For remove
#include <filesystem>
#include <json/json.h>     // jsoncpp library

#pragma comment(lib, "wininet.lib")

using namespace std;

// ================================================================
// THREAT INTELLIGENCE ENGINE
// ================================================================

class ThreatIntelligence {
private:
    // Threat databases
    unordered_set<string> known_malware_hashes;
    unordered_set<string> malicious_ips;
    unordered_set<string> malicious_domains;
    unordered_map<string, int> ip_reputation;  // IP -> reputation score (0-100)
    unordered_map<string, string> hash_family;  // Hash -> malware family name

    mutable mutex intel_mutex;  // mutable for const member functions

    // Update tracking
    uint64_t last_update_time;
    bool auto_update_enabled;
    thread update_thread;
    bool running;

    // Cache file paths
    wstring cache_directory;
    wstring hash_cache_file;
    wstring ip_cache_file;

public:
    ThreatIntelligence();
    ~ThreatIntelligence();

    // Initialization
    bool Initialize(const wstring& cache_dir);
    void Shutdown();

    // Threat lookups
    bool IsMalwareHash(const string& sha256);
    bool IsMaliciousIP(const string& ip);
    bool IsMaliciousDomain(const string& domain);
    int GetIPReputation(const string& ip);
    string GetMalwareFamily(const string& sha256);

    // Threat additions (from external sources or local detections)
    void AddMalwareHash(const string& sha256, const string& family = "Unknown");
    void AddMaliciousIP(const string& ip, int reputation = 0);
    void AddMaliciousDomain(const string& domain);

    // Bulk operations
    void AddMalwareHashes(const vector<string>& hashes);
    void AddMaliciousIPs(const vector<string>& ips);

    // Cache management
    bool LoadFromCache();
    bool SaveToCache();
    void ClearCache();

    // Online updates
    void EnableAutoUpdate(bool enable);
    bool UpdateFromFeeds();

    // Statistics
    size_t GetMalwareHashCount() const;
    size_t GetMaliciousIPCount() const;
    uint64_t GetLastUpdateTime() const;

private:
    // Update workers
    void AutoUpdateThread();

    // Feed parsers
    bool UpdateFromAbuseIPDB();
    bool UpdateFromVirusTotal();
    bool UpdateFromMalwareBazaar();
    bool UpdateFromCustomFeed(const string& url);

    // HTTP helpers
    string DownloadString(const string& url);
    bool ParseJSONFeed(const string& json_data);

    // File I/O
    bool LoadHashCache();
    bool LoadIPCache();
    bool SaveHashCache();
    bool SaveIPCache();
};

// ================================================================
// IMPLEMENTATION
// ================================================================

inline ThreatIntelligence::ThreatIntelligence()
    : last_update_time(0), auto_update_enabled(false), running(false) {

    cache_directory = L"C:\\SysOptima_Intel";
    hash_cache_file = cache_directory + L"\\malware_hashes.txt";
    ip_cache_file = cache_directory + L"\\malicious_ips.txt";

    // Create directory if it doesn't exist
    CreateDirectoryW(cache_directory.c_str(), NULL);
}

inline ThreatIntelligence::~ThreatIntelligence() {
    Shutdown();
}

inline bool ThreatIntelligence::Initialize(const wstring& cache_dir) {
    cache_directory = cache_dir;
    hash_cache_file = cache_directory + L"\\malware_hashes.txt";
    ip_cache_file = cache_directory + L"\\malicious_ips.txt";

    CreateDirectoryW(cache_directory.c_str(), NULL);

    // Load cached data
    bool loaded = LoadFromCache();

    wcout << L"[INTEL] Initialized with " << known_malware_hashes.size()
        << L" hashes, " << malicious_ips.size() << L" IPs" << endl;

    return loaded;
}

inline void ThreatIntelligence::Shutdown() {
    running = false;
    if (update_thread.joinable()) {
        update_thread.join();
    }
    SaveToCache();
}

// ================================================================
// THREAT LOOKUPS
// ================================================================

inline bool ThreatIntelligence::IsMalwareHash(const string& sha256) {
    lock_guard<mutex> lock(intel_mutex);
    return known_malware_hashes.count(sha256) > 0;
}

inline bool ThreatIntelligence::IsMaliciousIP(const string& ip) {
    lock_guard<mutex> lock(intel_mutex);
    return malicious_ips.count(ip) > 0;
}

inline bool ThreatIntelligence::IsMaliciousDomain(const string& domain) {
    lock_guard<mutex> lock(intel_mutex);
    return malicious_domains.count(domain) > 0;
}

inline int ThreatIntelligence::GetIPReputation(const string& ip) {
    lock_guard<mutex> lock(intel_mutex);
    auto it = ip_reputation.find(ip);
    if (it != ip_reputation.end()) {
        return it->second;
    }
    return 50;  // Neutral reputation
}

inline string ThreatIntelligence::GetMalwareFamily(const string& sha256) {
    lock_guard<mutex> lock(intel_mutex);
    auto it = hash_family.find(sha256);
    if (it != hash_family.end()) {
        return it->second;
    }
    return "Unknown";
}

// ================================================================
// THREAT ADDITIONS
// ================================================================

inline void ThreatIntelligence::AddMalwareHash(const string& sha256, const string& family) {
    lock_guard<mutex> lock(intel_mutex);
    known_malware_hashes.insert(sha256);
    hash_family[sha256] = family;
}

inline void ThreatIntelligence::AddMaliciousIP(const string& ip, int reputation) {
    lock_guard<mutex> lock(intel_mutex);
    malicious_ips.insert(ip);
    ip_reputation[ip] = reputation;
}

inline void ThreatIntelligence::AddMaliciousDomain(const string& domain) {
    lock_guard<mutex> lock(intel_mutex);
    malicious_domains.insert(domain);
}

inline void ThreatIntelligence::AddMalwareHashes(const vector<string>& hashes) {
    lock_guard<mutex> lock(intel_mutex);
    for (const auto& hash : hashes) {
        known_malware_hashes.insert(hash);
    }
}

inline void ThreatIntelligence::AddMaliciousIPs(const vector<string>& ips) {
    lock_guard<mutex> lock(intel_mutex);
    for (const auto& ip : ips) {
        malicious_ips.insert(ip);
        ip_reputation[ip] = 0;  // Worst reputation
    }
}

// ================================================================
// CACHE MANAGEMENT
// ================================================================

inline bool ThreatIntelligence::LoadFromCache() {
    bool success = true;
    success &= LoadHashCache();
    success &= LoadIPCache();
    return success;
}

inline bool ThreatIntelligence::SaveToCache() {
    bool success = true;
    success &= SaveHashCache();
    success &= SaveIPCache();
    return success;
}

inline void ThreatIntelligence::ClearCache() {
    lock_guard<mutex> lock(intel_mutex);
    known_malware_hashes.clear();
    malicious_ips.clear();
    malicious_domains.clear();
    ip_reputation.clear();
    hash_family.clear();
}

inline bool ThreatIntelligence::LoadHashCache() {
    ifstream file{ std::filesystem::path(hash_cache_file) };
    if (!file.is_open()) {
        // File doesn't exist yet - this is normal on first run
        return false;
    }

    lock_guard<mutex> lock(intel_mutex);
    string line;
    try {
        while (getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;

            // Format: HASH|FAMILY
            size_t pos = line.find('|');
            if (pos != string::npos) {
                string hash = line.substr(0, pos);
                string family = line.substr(pos + 1);
                known_malware_hashes.insert(hash);
                hash_family[hash] = family;
            }
            else {
                known_malware_hashes.insert(line);
            }
        }
    }
    catch (const exception& e) {
        wcout << L"[ERROR] Failed to load hash cache: " << e.what() << endl;
        file.close();
        return false;
    }

    file.close();
    return true;
}

inline bool ThreatIntelligence::LoadIPCache() {
    ifstream file{ std::filesystem::path(ip_cache_file) };
    if (!file.is_open()) {
        // File doesn't exist yet - this is normal on first run
        return false;
    }

    lock_guard<mutex> lock(intel_mutex);
    string line;
    try {
        while (getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;

            // Format: IP|REPUTATION
            size_t pos = line.find('|');
            if (pos != string::npos) {
                string ip = line.substr(0, pos);
                try {
                    int rep = stoi(line.substr(pos + 1));
                    malicious_ips.insert(ip);
                    ip_reputation[ip] = rep;
                }
                catch (const exception&) {
                    // Invalid reputation value, skip this line
                    continue;
                }
            }
            else {
                malicious_ips.insert(line);
                ip_reputation[line] = 0;
            }
        }
    }
    catch (const exception& e) {
        wcout << L"[ERROR] Failed to load IP cache: " << e.what() << endl;
        file.close();
        return false;
    }

    file.close();
    return true;
}

inline bool ThreatIntelligence::SaveHashCache() {
    ofstream file{ std::filesystem::path(hash_cache_file) };
    if (!file.is_open()) {
        wcout << L"[ERROR] Failed to create hash cache file" << endl;
        return false;
    }

    lock_guard<mutex> lock(intel_mutex);
    try {
        file << "# SysOptima Malware Hash Cache\n";
        file << "# Format: HASH|FAMILY\n";

        for (const auto& hash : known_malware_hashes) {
            file << hash;

            auto it = hash_family.find(hash);
            if (it != hash_family.end()) {
                file << "|" << it->second;
            }
            file << "\n";
        }
    }
    catch (const exception& e) {
        wcout << L"[ERROR] Failed to write hash cache: " << e.what() << endl;
        file.close();
        return false;
    }

    file.close();
    return true;
}

inline bool ThreatIntelligence::SaveIPCache() {
    ofstream file{ std::filesystem::path(ip_cache_file) };
    if (!file.is_open()) {
        wcout << L"[ERROR] Failed to create IP cache file" << endl;
        return false;
    }

    lock_guard<mutex> lock(intel_mutex);
    try {
        file << "# SysOptima Malicious IP Cache\n";
        file << "# Format: IP|REPUTATION\n";

        for (const auto& ip : malicious_ips) {
            file << ip;

            auto it = ip_reputation.find(ip);
            if (it != ip_reputation.end()) {
                file << "|" << it->second;
            }
            file << "\n";
        }
    }
    catch (const exception& e) {
        wcout << L"[ERROR] Failed to write IP cache: " << e.what() << endl;
        file.close();
        return false;
    }

    file.close();
    return true;
}

// ================================================================
// AUTO UPDATE
// ================================================================

inline void ThreatIntelligence::EnableAutoUpdate(bool enable) {
    auto_update_enabled = enable;

    if (enable && !running) {
        running = true;
        update_thread = thread(&ThreatIntelligence::AutoUpdateThread, this);
    }
    else if (!enable && running) {
        running = false;
        if (update_thread.joinable()) {
            update_thread.join();
        }
    }
}

inline void ThreatIntelligence::AutoUpdateThread() {
    const uint64_t UPDATE_INTERVAL = 3600000;  // 1 hour

    while (running) {
        Sleep(UPDATE_INTERVAL);

        if (auto_update_enabled) {
            wcout << L"[INTEL] Starting automatic threat feed update..." << endl;
            UpdateFromFeeds();
        }
    }
}

inline bool ThreatIntelligence::UpdateFromFeeds() {
    wcout << L"[INTEL] Updating threat intelligence feeds..." << endl;

    bool success = true;

    // Update from various sources
    success &= UpdateFromMalwareBazaar();
    success &= UpdateFromAbuseIPDB();

    if (success) {
        last_update_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        SaveToCache();

        wcout << L"[INTEL] Update complete: " << known_malware_hashes.size()
            << L" hashes, " << malicious_ips.size() << L" IPs" << endl;
    }

    return success;
}

// ================================================================
// FEED PARSERS
// ================================================================

inline bool ThreatIntelligence::UpdateFromMalwareBazaar() {
    // MalwareBazaar recent samples (free API)
    string url = "https://mb-api.abuse.ch/api/v1/";

    // In production, you'd use their API properly
    // This is a simplified example
    wcout << L"[INTEL] Would update from MalwareBazaar (API key required)" << endl;

    // Example: Add some known bad hashes (you'd get these from the API)
    // For now, just return true to show the structure works
    return true;
}

inline bool ThreatIntelligence::UpdateFromAbuseIPDB() {
    // AbuseIPDB API (requires API key)
    wcout << L"[INTEL] Would update from AbuseIPDB (API key required)" << endl;

    // In production, you'd download their blacklist
    // This is a simplified example
    return true;
}

// TODO: Implement when ready for production threat feeds
inline bool ThreatIntelligence::UpdateFromVirusTotal() {
    // VirusTotal API has restrictive free tier (4 req/min)
    // Placeholder for future implementation
    wcout << L"[INTEL] VirusTotal integration not yet implemented" << endl;
    return true;
}

inline bool ThreatIntelligence::UpdateFromCustomFeed(const string& url) {
    string data = DownloadString(url);
    if (data.empty()) {
        return false;
    }

    return ParseJSONFeed(data);
}

// ================================================================
// HTTP HELPERS
// ================================================================

inline string ThreatIntelligence::DownloadString(const string& url) {
    HINTERNET hInternet = InternetOpenA("SysOptima/1.0",
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL, 0);
    if (!hInternet) {
        wcout << L"[ERROR] Failed to initialize WinINet" << endl;
        return "";
    }

    // Set timeout (30 seconds)
    DWORD timeout = 30000;
    DWORD connectTimeout = timeout;
    DWORD receiveTimeout = timeout;
    InternetSetOption(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &connectTimeout, sizeof(connectTimeout));
    InternetSetOption(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &receiveTimeout, sizeof(receiveTimeout));

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(),
        NULL, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        wcout << L"[ERROR] Failed to open URL: " << wstring(url.begin(), url.end()) << endl;
        InternetCloseHandle(hInternet);
        return "";
    }

    string result;
    char buffer[4096];
    DWORD bytesRead;
    DWORD totalBytes = 0;
    const DWORD MAX_DOWNLOAD_SIZE = 10 * 1024 * 1024;  // 10MB limit

    try {
        while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            totalBytes += bytesRead;
            if (totalBytes > MAX_DOWNLOAD_SIZE) {
                wcout << L"[ERROR] Download size exceeded limit" << endl;
                break;
            }
            result.append(buffer, bytesRead);
        }
    }
    catch (const exception& e) {
        wcout << L"[ERROR] Download failed: " << e.what() << endl;
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return result;
}

inline bool ThreatIntelligence::ParseJSONFeed(const string& json_data) {
    // Simple JSON parsing for threat feeds
    // Format expected: {"hashes": ["hash1", "hash2"], "ips": ["ip1", "ip2"]}

    // This is a simplified parser - in production use a proper JSON library
    // like nlohmann/json or jsoncpp

    size_t hash_pos = json_data.find("\"hashes\"");
    if (hash_pos != string::npos) {
        // Extract hashes array
        size_t start = json_data.find("[", hash_pos);
        size_t end = json_data.find("]", start);
        if (start != string::npos && end != string::npos) {
            string hashes_section = json_data.substr(start + 1, end - start - 1);

            // Split by comma and extract hashes
            stringstream ss(hashes_section);
            string item;
            while (getline(ss, item, ',')) {
                // Remove quotes and whitespace
                item.erase(remove(item.begin(), item.end(), '\"'), item.end());
                item.erase(remove(item.begin(), item.end(), ' '), item.end());
                if (!item.empty()) {
                    AddMalwareHash(item);
                }
            }
        }
    }

    size_t ip_pos = json_data.find("\"ips\"");
    if (ip_pos != string::npos) {
        // Extract IPs array
        size_t start = json_data.find("[", ip_pos);
        size_t end = json_data.find("]", start);
        if (start != string::npos && end != string::npos) {
            string ips_section = json_data.substr(start + 1, end - start - 1);

            stringstream ss(ips_section);
            string item;
            while (getline(ss, item, ',')) {
                item.erase(remove(item.begin(), item.end(), '\"'), item.end());
                item.erase(remove(item.begin(), item.end(), ' '), item.end());
                if (!item.empty()) {
                    AddMaliciousIP(item);
                }
            }
        }
    }

    return true;
}

// ================================================================
// STATISTICS
// ================================================================

inline size_t ThreatIntelligence::GetMalwareHashCount() const {
    lock_guard<mutex> lock(intel_mutex);  // Now works because intel_mutex is mutable
    return known_malware_hashes.size();
}

inline size_t ThreatIntelligence::GetMaliciousIPCount() const {
    lock_guard<mutex> lock(intel_mutex);  // Now works because intel_mutex is mutable
    return malicious_ips.size();
}

inline uint64_t ThreatIntelligence::GetLastUpdateTime() const {
    return last_update_time;
}
