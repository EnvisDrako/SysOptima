"""
SysOptima Threat Intelligence Updater
Fetches threat data from free threat intelligence feeds and updates C++ cache
"""

import requests
import json
import time
import schedule
import threading
from datetime import datetime
from typing import List, Dict, Optional
import struct


class ThreatIntelUpdater:
    """Manages threat intelligence feed updates"""
    
    def __init__(self, control_queue=None):
        self.control_queue = control_queue
        self.last_update = {}
        self.stats = {
            'malwarebazaar_hashes': 0,
            'abuseipdb_ips': 0,
            'last_update_time': None,
            'update_count': 0
        }
        
        # API Configuration
        self.abuseipdb_api_key = None  # User needs to set this
        
        # Cache
        self.known_hashes = set()
        self.known_ips = set()
        
        print("[THREAT-INTEL] Threat Intelligence Updater initialized")
    
    def set_abuseipdb_key(self, api_key: str):
        """Set AbuseIPDB API key (get free key from abuseipdb.com)"""
        self.abuseipdb_api_key = api_key
        print("[THREAT-INTEL] AbuseIPDB API key configured")
    
    # ================================================================
    # MALWAREBAZAAR (FREE - NO API KEY NEEDED)
    # ================================================================
    
    def update_from_malwarebazaar(self) -> Dict:
        """
        Fetch recent malware hashes from MalwareBazaar
        API: https://bazaar.abuse.ch/api/
        FREE - No API key required
        """
        print("[THREAT-INTEL] Fetching from MalwareBazaar...")
        
        try:
            # Query for recent samples (last 100)
            url = "https://mb-api.abuse.ch/api/v1/"
            data = {
                "query": "get_recent",
                "selector": 100  # Last 100 samples
            }
            
            response = requests.post(url, data=data, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            
            if result.get('query_status') != 'ok':
                print(f"[THREAT-INTEL] MalwareBazaar error: {result.get('query_status')}")
                return {'success': False, 'hashes': 0}
            
            # Extract hashes
            new_hashes = []
            for sample in result.get('data', []):
                sha256 = sample.get('sha256_hash', '')
                if sha256 and sha256 not in self.known_hashes:
                    new_hashes.append({
                        'hash': sha256,
                        'family': sample.get('signature', 'Unknown'),
                        'file_type': sample.get('file_type', ''),
                        'first_seen': sample.get('first_seen', '')
                    })
                    self.known_hashes.add(sha256)
            
            print(f"[THREAT-INTEL] MalwareBazaar: Found {len(new_hashes)} new hashes")
            
            # Update C++ cache if we have new hashes
            if new_hashes and self.control_queue:
                self.send_hash_updates_to_cpp(new_hashes)
            
            self.stats['malwarebazaar_hashes'] += len(new_hashes)
            
            return {
                'success': True,
                'hashes': len(new_hashes),
                'details': new_hashes
            }
            
        except requests.exceptions.RequestException as e:
            print(f"[THREAT-INTEL] MalwareBazaar request failed: {e}")
            return {'success': False, 'hashes': 0}
        except Exception as e:
            print(f"[THREAT-INTEL] MalwareBazaar error: {e}")
            return {'success': False, 'hashes': 0}
    
    # ================================================================
    # ABUSEIPDB (FREE TIER - 1000 requests/day)
    # ================================================================
    
    def update_from_abuseipdb(self) -> Dict:
        """
        Fetch malicious IPs from AbuseIPDB
        API: https://www.abuseipdb.com/api.html
        FREE tier: 1000 requests/day
        Requires API key (free signup)
        """
        if not self.abuseipdb_api_key:
            print("[THREAT-INTEL] AbuseIPDB: API key not configured")
            print("              Get free key at: https://www.abuseipdb.com/register")
            return {'success': False, 'ips': 0}
        
        print("[THREAT-INTEL] Fetching from AbuseIPDB...")
        
        try:
            # Get blacklist (IPs with confidence >= 90%)
            url = "https://api.abuseipdb.com/api/v2/blacklist"
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            params = {
                'confidenceMinimum': 90,  # High confidence only
                'limit': 1000  # Max for free tier
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            
            # Extract IPs
            new_ips = []
            for entry in result.get('data', []):
                ip = entry.get('ipAddress', '')
                confidence = entry.get('abuseConfidenceScore', 0)
                
                if ip and ip not in self.known_ips:
                    new_ips.append({
                        'ip': ip,
                        'confidence': confidence,
                        'country': entry.get('countryCode', ''),
                        'last_seen': entry.get('lastReportedAt', '')
                    })
                    self.known_ips.add(ip)
            
            print(f"[THREAT-INTEL] AbuseIPDB: Found {len(new_ips)} new IPs")
            
            # Update C++ cache if we have new IPs
            if new_ips and self.control_queue:
                self.send_ip_updates_to_cpp(new_ips)
            
            self.stats['abuseipdb_ips'] += len(new_ips)
            
            return {
                'success': True,
                'ips': len(new_ips),
                'details': new_ips
            }
            
        except requests.exceptions.RequestException as e:
            print(f"[THREAT-INTEL] AbuseIPDB request failed: {e}")
            return {'success': False, 'ips': 0}
        except Exception as e:
            print(f"[THREAT-INTEL] AbuseIPDB error: {e}")
            return {'success': False, 'ips': 0}
    
    # ================================================================
    # C++ CACHE UPDATES (via Control Pipe)
    # ================================================================
    
    def send_hash_updates_to_cpp(self, hashes: List[Dict]):
        """
        Send hash updates to C++ via control pipe and cache files
        """
        print(f"[THREAT-INTEL] Processing {len(hashes)} hash updates for C++ engine")
        
        # 1. Update native C++ cache files
        import os
        intel_dir = r"C:\SysOptima_Intel"
        try:
            os.makedirs(intel_dir, exist_ok=True)
            hash_file = os.path.join(intel_dir, "malware_hashes.txt")
            
            existing = {}
            if os.path.exists(hash_file):
                with open(hash_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith('#') or not line.strip():
                            continue
                        parts = line.strip().split('|')
                        if len(parts) >= 2:
                            existing[parts[0]] = parts[1]
                        elif len(parts) == 1:
                            existing[parts[0]] = "Unknown"
            
            for h in hashes:
                existing[h['hash']] = h.get('family', 'Unknown')
                
            with open(hash_file, 'w', encoding='utf-8') as f:
                f.write("# SysOptima Malware Hash Cache\n")
                f.write("# Format: HASH|FAMILY\n")
                for h, fam in existing.items():
                    f.write(f"{h}|{fam}\n")
            print(f"[THREAT-INTEL] Successfully wrote hash cache updates to: {hash_file}")
        except Exception as e:
            print(f"[THREAT-INTEL] Failed to write hash cache to C++ directory: {e}")
            
        # 2. Live sync over Control Pipe if connected
        if self.control_queue:
            try:
                from protocol import CMD_UPDATE_THREAT_CACHE, pack_command
                for h in hashes:
                    cmd_bytes = pack_command(CMD_UPDATE_THREAT_CACHE, 0, h['hash'])
                    self.control_queue.put(cmd_bytes)
                print(f"[THREAT-INTEL] Dispatched {len(hashes)} hash updates directly to C++ control pipe")
            except Exception as e:
                print(f"[THREAT-INTEL] Failed to stream live hash updates to C++ pipe: {e}")
    
    def send_ip_updates_to_cpp(self, ips: List[Dict]):
        """Send IP updates to C++ via control pipe and cache files"""
        print(f"[THREAT-INTEL] Processing {len(ips)} IP updates for C++ engine")
        
        # 1. Update native C++ cache files
        import os
        intel_dir = r"C:\SysOptima_Intel"
        try:
            os.makedirs(intel_dir, exist_ok=True)
            ip_file = os.path.join(intel_dir, "malicious_ips.txt")
            
            existing = {}
            if os.path.exists(ip_file):
                with open(ip_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith('#') or not line.strip():
                            continue
                        parts = line.strip().split('|')
                        if len(parts) >= 2:
                            existing[parts[0]] = parts[1]
                        elif len(parts) == 1:
                            existing[parts[0]] = "0"
            
            for i in ips:
                existing[i['ip']] = str(i.get('confidence', 0))
                
            with open(ip_file, 'w', encoding='utf-8') as f:
                f.write("# SysOptima Malicious IP Cache\n")
                f.write("# Format: IP|REPUTATION\n")
                for ip, rep in existing.items():
                    f.write(f"{ip}|{rep}\n")
            print(f"[THREAT-INTEL] Successfully wrote IP cache updates to: {ip_file}")
        except Exception as e:
            print(f"[THREAT-INTEL] Failed to write IP cache to C++ directory: {e}")
    
    # ================================================================
    # SCHEDULED UPDATES
    # ================================================================
    
    def update_all_feeds(self):
        """Update all threat intelligence feeds"""
        print("\n" + "="*60)
        print(f"[THREAT-INTEL] Starting scheduled update at {datetime.now()}")
        print("="*60)
        
        start_time = time.time()
        
        # MalwareBazaar (always available)
        mb_result = self.update_from_malwarebazaar()
        
        # AbuseIPDB (if key configured)
        ab_result = self.update_from_abuseipdb()
        
        # Update stats
        self.stats['last_update_time'] = datetime.now().isoformat()
        self.stats['update_count'] += 1
        
        elapsed = time.time() - start_time
        
        print("="*60)
        print(f"[THREAT-INTEL] Update complete in {elapsed:.1f}s")
        print(f"               New Hashes: {mb_result.get('hashes', 0)}")
        print(f"               New IPs: {ab_result.get('ips', 0)}")
        print(f"               Total Hashes: {len(self.known_hashes)}")
        print(f"               Total IPs: {len(self.known_ips)}")
        print("="*60 + "\n")
    
    def start_auto_update(self, interval_hours: int = 1):
        """Start automatic updates on a schedule"""
        print(f"[THREAT-INTEL] Starting auto-update (every {interval_hours} hour(s))")
        
        # Initial update
        self.update_all_feeds()
        
        # Schedule updates
        schedule.every(interval_hours).hours.do(self.update_all_feeds)
        
        # Run scheduler in background
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        
        print(f"[THREAT-INTEL] Auto-update started")
    
    # ================================================================
    # MANUAL OPERATIONS
    # ================================================================
    
    def force_update(self):
        """Force an immediate update"""
        print("[THREAT-INTEL] Forcing immediate update...")
        self.update_all_feeds()
    
    def get_stats(self) -> Dict:
        """Get updater statistics"""
        return {
            **self.stats,
            'total_hashes': len(self.known_hashes),
            'total_ips': len(self.known_ips)
        }
    
    def export_threat_data(self, filepath: str):
        """Export all threat data to JSON"""
        data = {
            'export_time': datetime.now().isoformat(),
            'stats': self.get_stats(),
            'hashes': list(self.known_hashes),
            'ips': list(self.known_ips)
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[THREAT-INTEL] Exported threat data to {filepath}")


# ================================================================
# STANDALONE TESTING
# ================================================================

if __name__ == "__main__":
    print("Testing Threat Intelligence Updater...")
    print()
    
    # Create updater
    updater = ThreatIntelUpdater()
    
    # Test MalwareBazaar (free, no key needed)
    print("1. Testing MalwareBazaar...")
    mb_result = updater.update_from_malwarebazaar()
    print(f"   Result: {mb_result}")
    print()
    
    # Test AbuseIPDB (needs API key)
    print("2. Testing AbuseIPDB...")
    print("   To test, get free API key from: https://www.abuseipdb.com/register")
    print("   Then run:")
    print("   >>> updater.set_abuseipdb_key('YOUR_API_KEY_HERE')")
    print("   >>> updater.update_from_abuseipdb()")
    print()
    
    # Show stats
    print("3. Statistics:")
    stats = updater.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    print()
    
    # Export
    updater.export_threat_data("threat_intel_export.json")
    print()
    
    print("Test complete!")
    print()
    print("To use in production:")
    print("1. Get AbuseIPDB API key (free): https://www.abuseipdb.com/register")
    print("2. Configure in main.py:")
    print("   updater = ThreatIntelUpdater(control_queue)")
    print("   updater.set_abuseipdb_key('YOUR_KEY')")
    print("   updater.start_auto_update(interval_hours=1)")
