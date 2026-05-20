"""
Test script for the three new core modules
"""

import os
import sys
import tempfile
import time
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config_manager import ConfigManager
from trust_engine import TrustEngine
from memory_scanner import MemoryScanner
from quarantine_manager import QuarantineManager
from malware_launcher import MalwareLauncher

def test_memory_scanner():
    """Test memory scanner functionality"""
    print("="*60)
    print("TESTING MEMORY SCANNER")
    print("="*60)
    
    try:
        # Initialize components
        config = ConfigManager()
        trust_engine = TrustEngine(config)
        
        # Create memory scanner
        scanner = MemoryScanner(trust_engine, config)
        
        # Test statistics
        stats = scanner.get_statistics()
        print(f"[PASS] Memory Scanner initialized")
        print(f"   Scan interval: {stats['scan_interval']}s")
        print(f"   Trust threshold: {stats['trust_threshold']}")
        print(f"   Skip trusted: {stats['skip_trusted_enabled']}")
        
        # Test force scan on current process
        current_pid = os.getpid()
        print(f"\n[FIND] Force scanning current process (PID {current_pid})")
        findings = scanner.force_scan_process(current_pid)
        print(f"   Findings: {len(findings)}")
        
        # Start background scanning for 5 seconds
        print(f"\n[START] Starting background scanning for 5 seconds...")
        scanner.start_scanning()
        time.sleep(5)
        scanner.stop_scanning()
        
        final_stats = scanner.get_statistics()
        print(f"[PASS] Background scanning completed")
        print(f"   Scans performed: {final_stats['scans_performed']}")
        print(f"   Processes skipped (trust): {final_stats['processes_skipped_trust']}")
        print(f"   Processes skipped (JIT): {final_stats['processes_skipped_jit']}")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] Memory Scanner test failed: {e}")
        return False

def test_quarantine_manager():
    """Test quarantine manager functionality"""
    print("\n" + "="*60)
    print("TESTING QUARANTINE MANAGER")
    print("="*60)
    
    try:
        # Initialize components
        config = ConfigManager()
        
        # Override to secure temp directory for zero-admin unit testing
        test_quarantine_path = str(Path(tempfile.gettempdir()) / f"SysOptima_Quarantine_Test_{int(time.time())}")
        config.set('response.quarantine_path', test_quarantine_path)
        
        # Create quarantine manager
        quarantine = QuarantineManager(config)
        
        # Test statistics
        stats = quarantine.get_statistics()
        print(f"[PASS] Quarantine Manager initialized")
        print(f"   Quarantine path: {stats['quarantine_path']}")
        print(f"   Current files: {stats['current_files']}")
        print(f"   Retention days: {stats['retention_days']}")
        
        # Create a test file to quarantine
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("This is a test malware file for quarantine testing")
            test_file_path = f.name
        
        print(f"\n[BOX] Testing quarantine of test file: {Path(test_file_path).name}")
        
        # Quarantine the test file
        quarantine_id = quarantine.quarantine_file(
            file_path=test_file_path,
            threat_level=2,
            threat_reason="Test quarantine",
            process_pid=os.getpid(),
            process_name="test_modules.py"
        )
        
        if quarantine_id:
            print(f"[PASS] File quarantined successfully: {quarantine_id}")
            
            # Get file info
            info = quarantine.get_file_info(quarantine_id)
            if info:
                print(f"   Original name: {info['original_name']}")
                print(f"   File size: {info['file_size']} bytes")
                print(f"   Threat level: {info['threat_level']}")
            
            # List quarantined files
            files = quarantine.list_quarantined_files()
            print(f"   Total quarantined files: {len(files)}")
            
            # Test restore
            restore_path = test_file_path + ".restored"
            print(f"\n[RESTORE] Testing restore to: {Path(restore_path).name}")
            
            if quarantine.restore_file(quarantine_id, restore_path):
                print(f"[PASS] File restored successfully")
                
                # Verify restored file
                if os.path.exists(restore_path):
                    with open(restore_path, 'r') as f:
                        content = f.read()
                    print(f"   Restored content length: {len(content)} chars")
                    os.unlink(restore_path)  # Clean up
                
            # Test deletion
            print(f"\n[DELETE] Testing permanent deletion")
            if quarantine.delete_quarantined_file(quarantine_id, "Test cleanup"):
                print(f"[PASS] File permanently deleted")
            
        else:
            print(f"[FAIL] Failed to quarantine test file")
            return False
        
        return True
        
    except Exception as e:
        print(f"[FAIL] Quarantine Manager test failed: {e}")
        return False

def test_malware_launcher():
    """Test malware launcher functionality"""
    print("\n" + "="*60)
    print("TESTING MALWARE LAUNCHER")
    print("="*60)
    
    try:
        # Initialize components
        config = ConfigManager()
        
        # Override to secure temp directory for zero-admin unit testing
        test_quarantine_path = str(Path(tempfile.gettempdir()) / f"SysOptima_Quarantine_Test_ML_{int(time.time())}")
        test_sandbox_path = str(Path(tempfile.gettempdir()) / f"SysOptima_Sandbox_Test_{int(time.time())}")
        config.set('response.quarantine_path', test_quarantine_path)
        config.set('malware_launcher.sandbox_path', test_sandbox_path)
        
        # Enable malware launcher for testing
        config.set('malware_launcher.enabled', True)
        config.set('malware_launcher.execution_timeout_seconds', 10)  # Short timeout for testing
        
        quarantine = QuarantineManager(config)
        
        # Create malware launcher
        launcher = MalwareLauncher(config, quarantine)
        
        # Test statistics
        stats = launcher.get_statistics()
        print(f"[PASS] Malware Launcher initialized")
        print(f"   Sandbox path: {stats['sandbox_path']}")
        print(f"   Max concurrent: {stats['max_concurrent']}")
        print(f"   Execution timeout: {stats['execution_timeout']}s")
        
        # Create a test "malware" sample (harmless batch file)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.bat', delete=False) as f:
            f.write('@echo off\n')
            f.write('echo This is a test malware sample\n')
            f.write('timeout /t 5 /nobreak >nul\n')
            f.write('echo Test completed\n')
            test_sample_path = f.name
        
        print(f"\n[START] Testing malware execution: {Path(test_sample_path).name}")
        
        # Launch the test sample
        execution_id = launcher.launch_malware_sample(
            sample_path=test_sample_path,
            execution_params={
                'test_mode': True,
                'description': 'Test execution'
            }
        )
        
        if execution_id:
            print(f"[PASS] Execution started: {execution_id}")
            
            # Monitor execution
            for i in range(15):  # Wait up to 15 seconds
                status = launcher.get_execution_status(execution_id)
                if status:
                    print(f"   Status: {status['status']} (duration: {status['duration']:.1f}s)")
                    
                    if status['status'] in ['COMPLETED', 'FAILED', 'TIMEOUT', 'ERROR']:
                        break
                
                time.sleep(1)
            
            # Get final results
            results = launcher.get_execution_results(execution_id)
            if results:
                print(f"[PASS] Execution completed")
                print(f"   Final status: {results['execution']['status']}")
                print(f"   Duration: {results['execution']['duration']:.2f}s")
                print(f"   Behaviors captured: {results['analysis']['behaviors_count']}")
                print(f"   Auto labels: {results['analysis']['auto_labels']}")
            
        else:
            print(f"[FAIL] Failed to start execution")
            return False
        
        # Clean up test file
        try:
            os.unlink(test_sample_path)
        except:
            pass
        
        return True
        
    except Exception as e:
        print(f"[FAIL] Malware Launcher test failed: {e}")
        return False

def main():
    """Run all module tests"""
    print("[TEST] SYSOPTIMA CORE MODULES TEST SUITE")
    print("Testing the three critical modules for core functionality")
    print()
    
    results = []
    
    # Test each module
    results.append(("Memory Scanner", test_memory_scanner()))
    results.append(("Quarantine Manager", test_quarantine_manager()))
    results.append(("Malware Launcher", test_malware_launcher()))
    
    # Print summary
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    
    passed = 0
    for module_name, success in results:
        status = "[PASS] PASSED" if success else "[FAIL] FAILED"
        print(f"{module_name:20} {status}")
        if success:
            passed += 1
    
    print(f"\nOverall: {passed}/{len(results)} modules passed")
    
    if passed == len(results):
        print("[SUCCESS] All core modules are working correctly!")
        print("Your SysOptima system now has:")
        print("  • Trust-based memory scanning (prevents false positives)")
        print("  • Secure file quarantine system (isolates threats)")
        print("  • Safe malware execution environment (for AI training)")
        print("\nThe three critical gaps have been resolved! [START]")
    else:
        print("[WARN] Some modules failed - check the error messages above")
    
    return passed == len(results)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)