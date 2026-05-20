"""
SysOptima Trust Engine
Multi-layer trust scoring system to eliminate false positives
"""

import os
import json
from typing import Dict, List

class TrustEngine:
    """Calculate trust scores based on signature, path, and user overrides"""
    
    def __init__(self, config_manager=None):
        # Use ConfigManager if provided, otherwise fallback to separate file
        self.config_manager = config_manager
        self.signer_cache = {}  # High-speed signature certificate cache
        
        if config_manager:
            # Use trust settings from main config
            self.load_from_config_manager()
        else:
            # Legacy: separate trust_config.json
            self.config_path = 'trust_config.json'
            self.load_config()
        
        self.browser_processes = {
            'chrome.exe', 'msedge.exe', 'firefox.exe', 
            'brave.exe', 'opera.exe', 'vivaldi.exe',
            'iexplore.exe', 'safari.exe',
            'code.exe',  # VSCode
            'electron.exe',  # Electron apps
            'discord.exe', 'slack.exe', 'teams.exe'  # Common apps
        }

    def load_from_config_manager(self):
            """Load trust settings from ConfigManager"""
            self.trusted_signers = self.config_manager.get('trust.trusted_signers', {
                "Microsoft Corporation": 50,
                "Google LLC": 50,
                "Apple Inc.": 50
            })
            self.trusted_paths = self.config_manager.get('trust.trusted_paths', [
                "C:\\Windows\\System32\\",
                "C:\\Program Files\\"
            ])
            self.suspicious_paths = self.config_manager.get('trust.suspicious_paths', [
                "\\AppData\\Local\\Temp\\",
                "\\Downloads\\"
            ])
            self.user_whitelist = set(self.config_manager.get('trust.user_whitelist_hashes', []))
            self.user_blacklist = set(self.config_manager.get('trust.user_blacklist_hashes', []))
            self.system_processes = self.config_manager.get('trust.system_processes', [
                "svchost.exe", "lsass.exe", "csrss.exe"
            ])

    def load_config(self):
        """Load trust configuration"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config = json.load(f)
        else:
            # Create default config
            config = self.get_default_config()
            self.save_config(config)
        
        self.trusted_signers = config.get('trusted_signers', {})
        self.trusted_paths = config.get('trusted_paths', [])
        self.suspicious_paths = config.get('suspicious_paths', [])
        self.user_whitelist = set(config.get('user_whitelist_hashes', []))
        self.user_blacklist = set(config.get('user_blacklist_hashes', []))
        self.system_processes = config.get('system_processes', [])
    
    def get_default_config(self):
        """Default trust configuration"""
        return {
            "trusted_signers": {
                "Microsoft Corporation": 50,
                "Google LLC": 50,
                "Apple Inc.": 50,
                "Adobe Inc.": 40,
                "Mozilla Corporation": 40,
                "NVIDIA Corporation": 40
            },
            "trusted_paths": [
                "C:\\Windows\\System32\\",
                "C:\\Windows\\SysWOW64\\",
                "C:\\Program Files\\",
                "C:\\Program Files (x86)\\"
            ],
            "suspicious_paths": [
                "\\AppData\\Local\\Temp\\",
                "\\Downloads\\",
                "\\Users\\Public\\",
                "\\ProgramData\\"
            ],
            "system_processes": [
                "svchost.exe",
                "lsass.exe", 
                "csrss.exe",
                "services.exe",
                "wininit.exe",
                "winlogon.exe",
                "smss.exe"
            ],
            "user_whitelist_hashes": [],
            "user_blacklist_hashes": []
        }
    
    def save_config(self, config=None):
        """Save trust configuration"""
        if config is None:
            config = {
                "trusted_signers": self.trusted_signers,
                "trusted_paths": self.trusted_paths,
                "suspicious_paths": self.suspicious_paths,
                "system_processes": self.system_processes,
                "user_whitelist_hashes": list(self.user_whitelist),
                "user_blacklist_hashes": list(self.user_blacklist)
            }
        
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    def calculate_trust_score(self, process_info: Dict) -> int:
        """
        Calculate trust score (-100 to +100)
        Positive = Trusted, Negative = Suspicious
        """
        score = 0
        
        name = process_info.get('name', '').lower()
        full_path = process_info.get('full_path', '')
        is_signed = process_info.get('is_signed', False)
        origin = process_info.get('origin', 'Unknown')
        
        if name in self.browser_processes:
            return 100  # Absolute trust - NEVER kill browsers
        
        # Check if it's a browser child process
        for browser in self.browser_processes:
            if browser.replace('.exe', '') in name:
                return 100  # gpu-process.exe, renderer.exe, etc.

        # Layer 1: User Overrides (absolute)
        hash_val = self.compute_simple_hash(full_path)
        if hash_val in self.user_whitelist:
            return 100  # Absolute trust
        if hash_val in self.user_blacklist:
            return -100  # Absolute block
        
        # Layer 2: Digital Signature
        if is_signed:
            score += 30
            
            # Extract actual digital signer name using cached Authenticode check
            actual_signer = self.extract_signer_name(full_path)
            if actual_signer:
                matched_trusted = False
                for signer, trust_value in self.trusted_signers.items():
                    if signer.lower() in actual_signer.lower():
                        score += trust_value
                        matched_trusted = True
                        break
            else:
                # Fallback if signature extraction failed but is_signed is positive
                for signer, trust_value in self.trusted_signers.items():
                    if signer.lower() in full_path.lower():
                        score += trust_value
                        break
        else:
            score -= 30  # Unsigned penalty
        
        # Layer 3: Path-Based Trust
        for trusted_path in self.trusted_paths:
            if full_path.startswith(trusted_path):
                score += 20
                break
        
        for suspicious_path in self.suspicious_paths:
            if suspicious_path.lower() in full_path.lower():
                score -= 25
                break
        
        # Layer 4: System Process Validation
        if name in self.system_processes:
            # Check if in correct location
            if full_path.startswith("C:\\Windows\\System32\\") or \
               full_path.startswith("C:\\Windows\\SysWOW64\\"):
                score += 50  # Legitimate system process
            else:
                score -= 80  # MASQUERADING!
        
        # Layer 5: Origin Adjustment
        if origin == "Internet":
            score -= 20
        elif origin == "System":
            score += 10
        
        # Clamp to range
        return max(-100, min(100, score))
    
    def extract_signer_name(self, filepath: str) -> str:
        """Extracts the digital signer/publisher name using Windows PowerShell Authenticode API with caching"""
        if not filepath or not os.path.exists(filepath):
            return ""
        
        # Check cache first for high-performance sub-millisecond lookup
        if filepath in self.signer_cache:
            return self.signer_cache[filepath]
            
        signer_name = ""
        try:
            import subprocess
            import re
            # Query Authenticode Subject name
            cmd = [
                'powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                f"(Get-AuthenticodeSignature '{filepath}').SignerCertificate.Subject"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0)
            if result.returncode == 0:
                subject = result.stdout.strip()
                if subject:
                    # Parse out Organization name "O=..."
                    match = re.search(r'O="?([^,"]+)"?', subject)
                    if match:
                        signer_name = match.group(1).strip()
                    else:
                        signer_name = subject
        except Exception:
            pass
            
        self.signer_cache[filepath] = signer_name
        return signer_name

    def compute_simple_hash(self, path: str) -> str:
        """Simple hash for whitelist/blacklist (SHA256 of path for persistence)"""
        import hashlib
        return hashlib.sha256(path.lower().encode('utf-8', errors='ignore')).hexdigest()
    
    def add_to_whitelist(self, process_path: str):
        """Add process to whitelist"""
        hash_val = self.compute_simple_hash(process_path)
        self.user_whitelist.add(hash_val)
        self.save_config()
    
    def add_to_blacklist(self, process_path: str):
        """Add process to blacklist"""
        hash_val = self.compute_simple_hash(process_path)
        self.user_blacklist.add(hash_val)
        self.save_config()