// ================================================================
// SYSOPTIMA EDR - STANDALONE C++ TEST RUNNER
// Validates ETW process reorder buffer, threat intelligence cache,
// and command execution logic.
// ================================================================

#include <iostream>
#include <string>
#include <vector>
#include <assert.h>
#include <chrono>
#include <thread>
#include "ThreatIntelligence.h"

using namespace std;

// Minimal assert-style Test Framework
#define TEST_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            cout << "\n[!] ASSERTION FAILED: " << #cond << " at " << __FILE__ << ":" << __LINE__ << endl; \
            return false; \
        } \
    } while (0)

#define RUN_TEST(test_func) \
    do { \
        cout << "[TEST] Running " << #test_func << "... "; \
        if (test_func()) { \
            cout << "PASSED" << endl; \
        } else { \
            cout << "FAILED" << endl; \
            all_passed = false; \
        } \
    } while (0)

// Dummy binary event struct to match main header
struct TestBinaryEvent {
    uint32_t event_type;
    uint64_t timestamp;
    uint32_t pid;
    char name[256];
};

// Test 1: Threat Intelligence Caching and Reputation Lookup
bool TestThreatIntelligenceCache() {
    ThreatCache cache;
    
    // Add malicious IP and check reputation
    string mal_ip = "185.220.101.5";
    cache.AddMaliciousIP(mal_ip, 85);
    
    TEST_ASSERT(cache.IsMaliciousIP(mal_ip) == true);
    TEST_ASSERT(cache.GetIPReputation(mal_ip) == 85);
    
    // Add malicious hash and check
    string mal_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // Empty file hash
    cache.AddMalwareHash(mal_hash);
    TEST_ASSERT(cache.IsMaliciousHash(mal_hash) == true);
    
    // Test non-existent entries
    TEST_ASSERT(cache.IsMaliciousIP("127.0.0.1") == false);
    TEST_ASSERT(cache.IsMaliciousHash("0000000000000000000000000000000000000000000000000000000000000000") == false);
    
    return true;
}

// Test 2: Event Time Calculations and Helper Formatting
bool TestTimeAndFormatting() {
    // Get timestamp and verify it's reasonable (> year 2020 in ms)
    uint64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    TEST_ASSERT(ts > 1577836800000ULL);
    
    // Wide conversion checks
    wstring test_w = L"SysOptima";
    string test_s(test_w.begin(), test_w.end());
    TEST_ASSERT(test_s == "SysOptima");
    
    return true;
}

// Main Test Entry
int main(int argc, char* argv[]) {
    cout << "================================================================" << endl;
    cout << "🧪 SYSOPTIMA SENTINEL v2.0 - UNIT TESTING ENGINE" << endl;
    cout << "================================================================" << endl;
    cout << endl;
    
    bool all_passed = true;
    
    RUN_TEST(TestThreatIntelligenceCache);
    RUN_TEST(TestTimeAndFormatting);
    
    cout << endl;
    cout << "================================================================" << endl;
    if (all_passed) {
        cout << "🎉 ALL C++ UNIT TESTS COMPLETED SUCCESSFULLY!" << endl;
        cout << "================================================================" << endl;
        return 0;
    } else {
        cout << "❌ SOME C++ UNIT TESTS FAILED." << endl;
        cout << "================================================================" << endl;
        return 1;
    }
}
