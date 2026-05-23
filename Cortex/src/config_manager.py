"""
SysOptima Configuration Manager
Centralized configuration system with JSON persistence
"""

import json
import os
from typing import Any, Dict

class ConfigManager:
    """Manage all SysOptima configuration settings"""
    
    def __init__(self, config_file='sysoptima_config.json'):
        self.config_file = config_file
        self.config = {}
        self.mode_change_callback = None
        self.load_config()
    
    def load_config(self):
        """Load configuration from file or create defaults"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                print(f"[CONFIG] Loaded configuration from {self.config_file}")
            except Exception as e:
                print(f"[CONFIG] Error loading config: {e}")
                print(f"[CONFIG] Creating default configuration")
                self.config = self.get_default_config()
                self.save_config()
        else:
            print(f"[CONFIG] No config file found - creating defaults")
            self.config = self.get_default_config()
            self.save_config()
    
    def get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            "version": "2.0",
            
            "mode": "SMART",  # PRODUCTION | SMART | LEARNING
            
            "detection": {
                "threat_kill_threshold": 80,
                "threat_suspend_threshold": 40,
                "threat_monitor_threshold": 0,
                "memory_scan_enabled": True,
                "memory_scan_interval_ms": 10000,
                "network_scan_interval_ms": 5000,
                "aggregation_flush_ms": 100,
                "reorder_buffer_ms": 500,
                "max_events_per_pid_per_second": 10,
                "max_graph_nodes": 500,
                "node_fade_time_ms": 600000
            },
            
            "response": {
                "auto_kill_enabled": True,
                "auto_suspend_enabled": True,
                "require_confirmation_for_trusted": True,
                "suspend_auto_kill_timer_seconds": 60,
                "quarantine_path": "C:\\SysOptima_Quarantine",
                "cleanup_persistence": True,
                "network_isolation_enabled": False
            },
            
            "quarantine": {
                "max_file_size_mb": 100,
                "retention_days": 30,
                "auto_cleanup_enabled": True
            },
            
            "malware_launcher": {
                "enabled": False,
                "sandbox_path": "C:\\SysOptima_Sandbox",
                "execution_timeout_seconds": 300,
                "max_concurrent": 3,
                "auto_label_enabled": True,
                "vm_integration_enabled": False
            },
            
            "ui": {
                "dashboard_port": 8050,
                "update_interval_ms": 2000,
                "show_safe_processes": False,
                "auto_collapse_system": True,
                "theme": "dark",
                "max_threat_log_entries": 20
            },
            
            "trust": {
                "enable_signature_validation": True,
                "enable_path_validation": True,
                "enable_system_process_validation": True,
                "skip_memory_scan_for_trusted": True,
                "trust_threshold_skip_scan": 40,
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
            },
            
            "ai": {
                "enabled": False,
                "training_mode": False,
                "training_samples_required": 1000,
                "anomaly_threshold": 0.7,
                "model_path": "sysoptima_models.pkl",
                "auto_retrain_days": 30,
                "baseline_collection_mode": "auto"
            },
            
            "database": {
                "path": "sysoptima_events.db",
                "retention_days": 7,
                "auto_cleanup_enabled": True,
                "vacuum_on_startup": False
            },
            
            "threat_intel": {
                "enabled": False,
                "auto_update_enabled": False,
                "update_interval_hours": 24,
                "abuseipdb_api_key": "",
                "malwarebazaar_enabled": True
            },
            
            "logging": {
                "console_level": "INFO",
                "file_logging_enabled": False,
                "log_file_path": "sysoptima.log",
                "log_max_size_mb": 100
            }
        }
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            print(f"[CONFIG] Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"[CONFIG] Error saving config: {e}")
    
    def get(self, key_path: str, default=None) -> Any:
        """
        Get nested config value using dot notation
        Example: config.get('detection.threat_kill_threshold')
        """
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            # Dynamically expand environment variables if value is a string
            if isinstance(value, str):
                value = os.path.expandvars(value)
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any):
        """
        Set nested config value using dot notation
        Example: config.set('detection.threat_kill_threshold', 90)
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to parent
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set value
        config[keys[-1]] = value
        self.save_config()
    
    def get_mode(self) -> str:
        """Get current operating mode"""
        return self.config.get('mode', 'SMART')
    
    def set_mode(self, mode: str):
        """Set operating mode"""
        valid_modes = ['PRODUCTION', 'SMART', 'LEARNING']
        if mode in valid_modes:
            self.config['mode'] = mode
            self.save_config()
            print(f"[CONFIG] Mode changed to {mode}")
            if self.mode_change_callback:
                self.mode_change_callback(mode)
        else:
            print(f"[CONFIG] Invalid mode: {mode}. Valid: {valid_modes}")
    
    def reload(self):
        """Reload configuration from file"""
        self.load_config()
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        print("[CONFIG] Resetting to default configuration")
        self.config = self.get_default_config()
        self.save_config()
    
    def export_config(self, filepath: str):
        """Export current config to another file"""
        with open(filepath, 'w') as f:
            json.dump(self.config, f, indent=2)
        print(f"[CONFIG] Exported to {filepath}")
    
    def import_config(self, filepath: str):
        """Import config from another file"""
        with open(filepath, 'r') as f:
            self.config = json.load(f)
        self.save_config()
        print(f"[CONFIG] Imported from {filepath}")