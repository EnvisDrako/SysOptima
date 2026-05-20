"""
SysOptima Quarantine Manager
Safely isolates malicious files with metadata tracking and restore capability
"""

import os
import json
import shutil
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import threading
import sqlite3
from pathlib import Path
import win32api
import win32security
import win32con

class QuarantineManager:
    """Secure file quarantine system with metadata tracking"""
    
    def __init__(self, config_manager, database=None):
        self.config = config_manager
        self.database = database
        
        # Quarantine configuration
        self.quarantine_root = Path(config_manager.get('response.quarantine_path', 'C:\\SysOptima_Quarantine'))
        self.max_file_size = config_manager.get('quarantine.max_file_size_mb', 100) * 1024 * 1024  # 100MB default
        self.retention_days = config_manager.get('quarantine.retention_days', 30)
        self.auto_cleanup_enabled = config_manager.get('quarantine.auto_cleanup_enabled', True)
        
        # Quarantine structure
        self.files_dir = self.quarantine_root / 'files'
        self.metadata_dir = self.quarantine_root / 'metadata'
        self.logs_dir = self.quarantine_root / 'logs'
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'files_quarantined': 0,
            'files_restored': 0,
            'files_deleted': 0,
            'total_size_bytes': 0,
            'cleanup_runs': 0
        }
        
        # Initialize quarantine system
        self._initialize_quarantine()
        
        # Start cleanup thread if enabled
        if self.auto_cleanup_enabled:
            self._start_cleanup_thread()
    
    def _initialize_quarantine(self):
        """Initialize quarantine directory structure"""
        try:
            # Create directories
            self.quarantine_root.mkdir(parents=True, exist_ok=True)
            self.files_dir.mkdir(exist_ok=True)
            self.metadata_dir.mkdir(exist_ok=True)
            self.logs_dir.mkdir(exist_ok=True)
            
            # Set restrictive permissions (only SYSTEM and Administrators)
            self._set_quarantine_permissions()
            
            # Create quarantine database
            self._init_quarantine_db()
            
            # Load existing statistics
            self._load_statistics()
            
            print(f"[QUARANTINE] Initialized at: {self.quarantine_root}")
            print(f"[QUARANTINE] Current files: {len(self.list_quarantined_files())}")
            
        except Exception as e:
            print(f"[QUARANTINE] Initialization failed: {e}")
            raise
    
    def _set_quarantine_permissions(self):
        """Set restrictive permissions on quarantine directory"""
        try:
            # Get security descriptor
            sd = win32security.GetFileSecurity(
                str(self.quarantine_root),
                win32security.DACL_SECURITY_INFORMATION
            )
            
            # Create new DACL with restricted access
            dacl = win32security.ACL()
            
            # Add SYSTEM full control
            system_sid = win32security.LookupAccountName(None, "SYSTEM")[0]
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.GENERIC_ALL,
                system_sid
            )
            
            # Add Administrators full control
            admin_sid = win32security.LookupAccountName(None, "Administrators")[0]
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.GENERIC_ALL,
                admin_sid
            )
            
            # Add Current User full control to ensure active process usability
            try:
                current_user = win32api.GetUserName()
                user_sid = win32security.LookupAccountName(None, current_user)[0]
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    win32con.GENERIC_ALL,
                    user_sid
                )
            except Exception as ue:
                print(f"[QUARANTINE] Warning: Could not add current user to DACL: {ue}")
            
            # Set the DACL
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                str(self.quarantine_root),
                win32security.DACL_SECURITY_INFORMATION,
                sd
            )
            
            print("[QUARANTINE] Set restrictive permissions")
            
        except Exception as e:
            print(f"[QUARANTINE] Failed to set permissions: {e}")
    
    def _init_quarantine_db(self):
        """Initialize quarantine metadata database"""
        db_path = self.quarantine_root / 'quarantine.db'
        
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quarantined_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quarantine_id TEXT UNIQUE NOT NULL,
                    original_path TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    quarantine_time INTEGER NOT NULL,
                    threat_level INTEGER NOT NULL,
                    threat_reason TEXT,
                    process_pid INTEGER,
                    process_name TEXT,
                    user_name TEXT,
                    is_restored BOOLEAN DEFAULT 0,
                    restore_time INTEGER,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_quarantine_id ON quarantined_files(quarantine_id)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_quarantine_time ON quarantined_files(quarantine_time)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_file_hash ON quarantined_files(file_hash)
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"[QUARANTINE] Database initialization failed: {e}")
    
    def quarantine_file(self, file_path: str, threat_level: int, threat_reason: str, 
                       process_pid: int = None, process_name: str = None) -> Optional[str]:
        """
        Quarantine a malicious file
        Returns quarantine ID if successful, None if failed
        """
        
        with self.lock:
            try:
                file_path = Path(file_path)
                
                # Validate file exists
                if not file_path.exists():
                    print(f"[QUARANTINE] File not found: {file_path}")
                    return None
                
                # Check file size
                file_size = file_path.stat().st_size
                if file_size > self.max_file_size:
                    print(f"[QUARANTINE] File too large: {file_size} bytes (max: {self.max_file_size})")
                    return None
                
                # Generate quarantine ID
                quarantine_id = self._generate_quarantine_id(file_path)
                
                # Calculate file hash
                file_hash = self._calculate_file_hash(file_path)
                
                # Check for duplicates
                if self._is_duplicate(file_hash):
                    print(f"[QUARANTINE] Duplicate file already quarantined: {file_hash[:16]}...")
                    return self._get_quarantine_id_by_hash(file_hash)
                
                # Create quarantine paths
                quarantined_file = self.files_dir / quarantine_id
                metadata_file = self.metadata_dir / f"{quarantine_id}.json"
                
                # Get current user
                try:
                    user_name = win32api.GetUserName()
                except:
                    user_name = "Unknown"
                
                # Create metadata
                metadata = {
                    'quarantine_id': quarantine_id,
                    'original_path': str(file_path),
                    'original_name': file_path.name,
                    'file_hash': file_hash,
                    'file_size': file_size,
                    'quarantine_time': int(time.time()),
                    'threat_level': threat_level,
                    'threat_reason': threat_reason,
                    'process_pid': process_pid,
                    'process_name': process_name,
                    'user_name': user_name,
                    'original_permissions': self._get_file_permissions(file_path),
                    'original_attributes': file_path.stat().st_mode,
                    'original_timestamps': {
                        'created': file_path.stat().st_ctime,
                        'modified': file_path.stat().st_mtime,
                        'accessed': file_path.stat().st_atime
                    }
                }
                
                # Move file to quarantine (secure copy + delete)
                self._secure_move_file(file_path, quarantined_file)
                
                # Save metadata
                with open(metadata_file, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                # Update database
                self._add_to_database(metadata)
                
                # Update statistics
                self.stats['files_quarantined'] += 1
                self.stats['total_size_bytes'] += file_size
                
                # Log quarantine action
                self._log_action('QUARANTINE', quarantine_id, metadata)
                
                print(f"[QUARANTINE] [PASS] File quarantined: {file_path.name}")
                print(f"              ID: {quarantine_id}")
                print(f"              Reason: {threat_reason}")
                print(f"              Size: {file_size:,} bytes")
                
                return quarantine_id
                
            except Exception as e:
                print(f"[QUARANTINE] Failed to quarantine {file_path}: {e}")
                return None
    
    def restore_file(self, quarantine_id: str, restore_path: str = None) -> bool:
        """
        Restore a quarantined file
        Returns True if successful, False if failed
        """
        
        with self.lock:
            try:
                # Load metadata
                metadata = self._load_metadata(quarantine_id)
                if not metadata:
                    print(f"[QUARANTINE] Metadata not found for ID: {quarantine_id}")
                    return False
                
                # Check if already restored
                if metadata.get('is_restored', False):
                    print(f"[QUARANTINE] File already restored: {quarantine_id}")
                    return False
                
                # Determine restore path
                if restore_path is None:
                    restore_path = metadata['original_path']
                
                restore_path = Path(restore_path)
                quarantined_file = self.files_dir / quarantine_id
                
                # Validate quarantined file exists
                if not quarantined_file.exists():
                    print(f"[QUARANTINE] Quarantined file not found: {quarantine_id}")
                    return False
                
                # Create restore directory if needed
                restore_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Check if restore destination already exists
                if restore_path.exists():
                    backup_path = restore_path.with_suffix(f"{restore_path.suffix}.backup_{int(time.time())}")
                    shutil.move(str(restore_path), str(backup_path))
                    print(f"[QUARANTINE] Existing file backed up to: {backup_path.name}")
                
                # Restore file
                shutil.copy2(str(quarantined_file), str(restore_path))
                
                # Restore original permissions and timestamps
                self._restore_file_attributes(restore_path, metadata)
                
                # Update metadata
                metadata['is_restored'] = True
                metadata['restore_time'] = int(time.time())
                metadata['restore_path'] = str(restore_path)
                
                # Save updated metadata
                metadata_file = self.metadata_dir / f"{quarantine_id}.json"
                with open(metadata_file, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                # Update database
                self._update_database_restore(quarantine_id, int(time.time()))
                
                # Update statistics
                self.stats['files_restored'] += 1
                
                # Log restore action
                self._log_action('RESTORE', quarantine_id, metadata)
                
                print(f"[QUARANTINE] [PASS] File restored: {restore_path}")
                print(f"              From ID: {quarantine_id}")
                
                return True
                
            except Exception as e:
                print(f"[QUARANTINE] Failed to restore {quarantine_id}: {e}")
                return False
    
    def delete_quarantined_file(self, quarantine_id: str, reason: str = "Manual deletion") -> bool:
        """
        Permanently delete a quarantined file
        Returns True if successful, False if failed
        """
        
        with self.lock:
            try:
                # Load metadata
                metadata = self._load_metadata(quarantine_id)
                if not metadata:
                    print(f"[QUARANTINE] Metadata not found for ID: {quarantine_id}")
                    return False
                
                quarantined_file = self.files_dir / quarantine_id
                metadata_file = self.metadata_dir / f"{quarantine_id}.json"
                
                # Secure delete file
                if quarantined_file.exists():
                    self._secure_delete_file(quarantined_file)
                
                # Delete metadata
                if metadata_file.exists():
                    metadata_file.unlink()
                
                # Update database
                self._delete_from_database(quarantine_id)
                
                # Update statistics
                self.stats['files_deleted'] += 1
                self.stats['total_size_bytes'] -= metadata.get('file_size', 0)
                
                # Log deletion
                metadata['deletion_reason'] = reason
                self._log_action('DELETE', quarantine_id, metadata)
                
                print(f"[QUARANTINE] [PASS] File permanently deleted: {quarantine_id}")
                print(f"              Reason: {reason}")
                
                return True
                
            except Exception as e:
                print(f"[QUARANTINE] Failed to delete {quarantine_id}: {e}")
                return False
    
    def list_quarantined_files(self, include_restored: bool = False) -> List[Dict]:
        """Get list of quarantined files"""
        
        try:
            db_path = self.quarantine_root / 'quarantine.db'
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if include_restored:
                cursor.execute('SELECT * FROM quarantined_files ORDER BY quarantine_time DESC')
            else:
                cursor.execute('SELECT * FROM quarantined_files WHERE is_restored = 0 ORDER BY quarantine_time DESC')
            
            files = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return files
            
        except Exception as e:
            print(f"[QUARANTINE] Failed to list files: {e}")
            return []
    
    def get_file_info(self, quarantine_id: str) -> Optional[Dict]:
        """Get detailed information about a quarantined file"""
        
        try:
            metadata = self._load_metadata(quarantine_id)
            if not metadata:
                return None
            
            # Add current status
            quarantined_file = self.files_dir / quarantine_id
            metadata['quarantine_file_exists'] = quarantined_file.exists()
            metadata['quarantine_file_size'] = quarantined_file.stat().st_size if quarantined_file.exists() else 0
            
            return metadata
            
        except Exception as e:
            print(f"[QUARANTINE] Failed to get file info: {e}")
            return None
    
    def cleanup_old_files(self, days: int = None) -> int:
        """
        Clean up old quarantined files
        Returns number of files cleaned up
        """
        
        if days is None:
            days = self.retention_days
        
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        cleaned_count = 0
        
        try:
            files = self.list_quarantined_files(include_restored=True)
            
            for file_info in files:
                if file_info['quarantine_time'] < cutoff_time:
                    if self.delete_quarantined_file(file_info['quarantine_id'], f"Auto-cleanup after {days} days"):
                        cleaned_count += 1
            
            self.stats['cleanup_runs'] += 1
            
            if cleaned_count > 0:
                print(f"[QUARANTINE] Cleaned up {cleaned_count} old files (older than {days} days)")
            
            return cleaned_count
            
        except Exception as e:
            print(f"[QUARANTINE] Cleanup failed: {e}")
            return 0
    
    def get_statistics(self) -> Dict:
        """Get quarantine statistics"""
        
        # Update current statistics
        files = self.list_quarantined_files(include_restored=True)
        current_files = len([f for f in files if not f['is_restored']])
        restored_files = len([f for f in files if f['is_restored']])
        
        return {
            **self.stats,
            'current_files': current_files,
            'restored_files': restored_files,
            'quarantine_path': str(self.quarantine_root),
            'retention_days': self.retention_days,
            'max_file_size_mb': self.max_file_size // (1024 * 1024),
            'total_size_mb': self.stats['total_size_bytes'] / (1024 * 1024)
        }
    
    def _generate_quarantine_id(self, file_path: Path) -> str:
        """Generate unique quarantine ID"""
        timestamp = int(time.time() * 1000)  # milliseconds
        file_hash = hashlib.md5(str(file_path).encode()).hexdigest()[:8]
        return f"Q_{timestamp}_{file_hash}"
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    def _is_duplicate(self, file_hash: str) -> bool:
        """Check if file hash already exists in quarantine"""
        try:
            db_path = self.quarantine_root / 'quarantine.db'
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM quarantined_files WHERE file_hash = ? AND is_restored = 0', (file_hash,))
            count = cursor.fetchone()[0]
            conn.close()
            
            return count > 0
            
        except Exception:
            return False
    
    def _get_quarantine_id_by_hash(self, file_hash: str) -> Optional[str]:
        """Get quarantine ID by file hash"""
        try:
            db_path = self.quarantine_root / 'quarantine.db'
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            cursor.execute('SELECT quarantine_id FROM quarantined_files WHERE file_hash = ? AND is_restored = 0 LIMIT 1', (file_hash,))
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result else None
            
        except Exception:
            return None
    
    def _secure_move_file(self, source: Path, destination: Path):
        """Securely move file (copy + secure delete original)"""
        # Copy file
        shutil.copy2(str(source), str(destination))
        
        # Verify copy
        if not destination.exists():
            raise Exception("File copy failed")
        
        # Secure delete original
        self._secure_delete_file(source)
    
    def _secure_delete_file(self, file_path: Path):
        """Securely delete file (overwrite + delete)"""
        try:
            if not file_path.exists():
                return
            
            file_size = file_path.stat().st_size
            
            # Overwrite with random data (simplified secure delete)
            with open(file_path, 'r+b') as f:
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
            
            # Delete file
            file_path.unlink()
            
        except Exception as e:
            print(f"[QUARANTINE] Secure delete failed: {e}")
            # Fallback to normal delete
            try:
                file_path.unlink()
            except:
                pass
    
    def _get_file_permissions(self, file_path: Path) -> Dict:
        """Get file permissions (simplified)"""
        try:
            stat_info = file_path.stat()
            return {
                'mode': stat_info.st_mode,
                'uid': stat_info.st_uid if hasattr(stat_info, 'st_uid') else 0,
                'gid': stat_info.st_gid if hasattr(stat_info, 'st_gid') else 0
            }
        except:
            return {}
    
    def _restore_file_attributes(self, file_path: Path, metadata: Dict):
        """Restore original file attributes"""
        try:
            # Restore timestamps
            timestamps = metadata.get('original_timestamps', {})
            if timestamps:
                os.utime(str(file_path), (timestamps.get('accessed', time.time()), 
                                        timestamps.get('modified', time.time())))
        except Exception as e:
            print(f"[QUARANTINE] Failed to restore attributes: {e}")
    
    def _load_metadata(self, quarantine_id: str) -> Optional[Dict]:
        """Load metadata for quarantined file"""
        try:
            metadata_file = self.metadata_dir / f"{quarantine_id}.json"
            if not metadata_file.exists():
                return None
            
            with open(metadata_file, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            print(f"[QUARANTINE] Failed to load metadata: {e}")
            return None
    
    def _add_to_database(self, metadata: Dict):
        """Add quarantined file to database"""
        try:
            db_path = self.quarantine_root / 'quarantine.db'
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO quarantined_files 
                (quarantine_id, original_path, original_name, file_hash, file_size, 
                 quarantine_time, threat_level, threat_reason, process_pid, process_name, user_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metadata['quarantine_id'],
                metadata['original_path'],
                metadata['original_name'],
                metadata['file_hash'],
                metadata['file_size'],
                metadata['quarantine_time'],
                metadata['threat_level'],
                metadata['threat_reason'],
                metadata.get('process_pid'),
                metadata.get('process_name'),
                metadata['user_name']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"[QUARANTINE] Database insert failed: {e}")
    
    def _update_database_restore(self, quarantine_id: str, restore_time: int):
        """Update database with restore information"""
        try:
            db_path = self.quarantine_root / 'quarantine.db'
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE quarantined_files 
                SET is_restored = 1, restore_time = ?
                WHERE quarantine_id = ?
            ''', (restore_time, quarantine_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"[QUARANTINE] Database update failed: {e}")
    
    def _delete_from_database(self, quarantine_id: str):
        """Delete quarantined file from database"""
        try:
            db_path = self.quarantine_root / 'quarantine.db'
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM quarantined_files WHERE quarantine_id = ?', (quarantine_id,))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"[QUARANTINE] Database delete failed: {e}")
    
    def _log_action(self, action: str, quarantine_id: str, metadata: Dict):
        """Log quarantine action"""
        try:
            log_file = self.logs_dir / f"quarantine_{datetime.now().strftime('%Y%m%d')}.log"
            
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': action,
                'quarantine_id': quarantine_id,
                'file_name': metadata.get('original_name', 'Unknown'),
                'file_path': metadata.get('original_path', 'Unknown'),
                'threat_level': metadata.get('threat_level', 0),
                'threat_reason': metadata.get('threat_reason', 'Unknown'),
                'user': metadata.get('user_name', 'Unknown')
            }
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            print(f"[QUARANTINE] Logging failed: {e}")
    
    def _load_statistics(self):
        """Load statistics from database"""
        try:
            files = self.list_quarantined_files(include_restored=True)
            
            self.stats['files_quarantined'] = len(files)
            self.stats['files_restored'] = len([f for f in files if f['is_restored']])
            self.stats['total_size_bytes'] = sum(f['file_size'] for f in files if not f['is_restored'])
            
        except Exception as e:
            print(f"[QUARANTINE] Failed to load statistics: {e}")
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_loop():
            while True:
                try:
                    time.sleep(24 * 60 * 60)  # Run daily
                    self.cleanup_old_files()
                except Exception as e:
                    print(f"[QUARANTINE] Cleanup thread error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
        print("[QUARANTINE] Auto-cleanup thread started (daily)")