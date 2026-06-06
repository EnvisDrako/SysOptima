"""
SysOptima Event Database
Provides SQLite persistence for events, threats, patterns, and AI predictions
"""

import sqlite3
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import threading
import os


class EventDatabase:
    """SQLite database for event logging and forensic analysis"""
    
    def __init__(self, db_path: str = "sysoptima_events.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.connection = None
        self.init_database()
    
    def init_database(self):
        """Create database schema if not exists"""
        with self.lock:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row  # Return rows as dicts
            cursor = self.connection.cursor()
            
            # Table 1: Raw Events
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    event_type INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    ppid INTEGER,
                    process_name TEXT NOT NULL,
                    full_path TEXT,
                    threat_level INTEGER DEFAULT 0,
                    is_signed BOOLEAN DEFAULT 1,
                    origin_tag TEXT,
                    file_writes INTEGER DEFAULT 0,
                    registry_writes INTEGER DEFAULT 0,
                    network_connections INTEGER DEFAULT 0,
                    extra_data TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for events table
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_threat ON events(threat_level)')
            
            # Table 2: Detected Threats
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    threat_level INTEGER NOT NULL,
                    action_taken TEXT NOT NULL,
                    semantic_tags TEXT,
                    mitre_techniques TEXT,
                    ai_anomaly BOOLEAN DEFAULT 0,
                    ai_confidence REAL DEFAULT 0.0,
                    pattern_matches TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for threats table
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_pid ON threats(pid)')
            
            # Table 3: Attack Pattern Matches
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS pattern_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    pattern_name TEXT NOT NULL,
                    threat_multiplier REAL NOT NULL,
                    mitre_techniques TEXT,
                    event_count INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for pattern_matches table
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_patterns_timestamp ON pattern_matches(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_patterns_name ON pattern_matches(pattern_name)')
            
            # Table 4: AI Predictions
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ai_predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    is_anomaly BOOLEAN NOT NULL,
                    confidence REAL NOT NULL,
                    isolation_forest_flag BOOLEAN DEFAULT 0,
                    svm_flag BOOLEAN DEFAULT 0,
                    features TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for ai_predictions table
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_timestamp ON ai_predictions(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_anomaly ON ai_predictions(is_anomaly)')
            
            # Table 5: Graph Snapshots (periodic saves)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS graph_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    node_count INTEGER NOT NULL,
                    edge_count INTEGER NOT NULL,
                    threat_count INTEGER NOT NULL,
                    graph_data TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for graph_snapshots table
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON graph_snapshots(timestamp)')
            
            # Table 6: AI Training Session Logs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ai_training_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    samples_count INTEGER NOT NULL,
                    features_count INTEGER NOT NULL,
                    training_duration REAL NOT NULL,
                    iso_forest_anomalies INTEGER DEFAULT 0,
                    svm_anomalies INTEGER DEFAULT 0,
                    status TEXT NOT NULL,
                    model_metadata TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index for ai_training_logs table
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_training_timestamp ON ai_training_logs(timestamp)')
            
            self.connection.commit()
            print(f"[DB] Database initialized: {self.db_path}")
    
    def insert_event(self, event: Dict):
        """Insert raw event"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO events (
                    timestamp, event_type, pid, ppid, process_name, full_path,
                    threat_level, is_signed, origin_tag, file_writes,
                    registry_writes, network_connections, extra_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.get('timestamp', int(time.time() * 1000)),
                event.get('event_type', 0),
                event.get('pid', 0),
                event.get('ppid', 0),
                event.get('name', 'unknown'),
                event.get('full_path', ''),
                event.get('threat_level', 0),
                event.get('is_signed', True),
                event.get('origin', ''),
                event.get('file_writes', 0),
                event.get('registry_writes', 0),
                event.get('network_connections', 0),
                event.get('extra_data', '')
            ))
            self.connection.commit()
            return cursor.lastrowid
    
    def insert_threat(self, threat: Dict):
        """Insert detected threat"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO threats (
                    timestamp, pid, process_name, threat_level, action_taken,
                    semantic_tags, mitre_techniques, ai_anomaly, ai_confidence,
                    pattern_matches
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat.get('timestamp', int(time.time() * 1000)),
                threat.get('pid', 0),
                threat.get('name', 'unknown'),
                threat.get('threat_level', 0),
                threat.get('action', 'none'),
                json.dumps(threat.get('tags', [])),
                json.dumps(threat.get('mitre', [])),
                threat.get('ai_anomaly', False),
                threat.get('ai_confidence', 0.0),
                json.dumps(threat.get('patterns', []))
            ))
            self.connection.commit()
            return cursor.lastrowid
    
    def insert_pattern_match(self, pattern: Dict):
        """Insert attack pattern match"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO pattern_matches (
                    timestamp, pid, process_name, pattern_name,
                    threat_multiplier, mitre_techniques, event_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                pattern.get('timestamp', int(time.time() * 1000)),
                pattern.get('pid', 0),
                pattern.get('name', 'unknown'),
                pattern.get('pattern', 'unknown'),
                pattern.get('multiplier', 1.0),
                json.dumps(pattern.get('mitre', [])),
                pattern.get('event_count', 0)
            ))
            self.connection.commit()
            return cursor.lastrowid
    
    def insert_ai_prediction(self, prediction: Dict):
        """Insert AI anomaly prediction"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO ai_predictions (
                    timestamp, pid, process_name, is_anomaly, confidence,
                    isolation_forest_flag, svm_flag, features
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                prediction.get('timestamp', int(time.time() * 1000)),
                prediction.get('pid', 0),
                prediction.get('name', 'unknown'),
                prediction.get('is_anomaly', False),
                prediction.get('confidence', 0.0),
                prediction.get('iso_forest', False),
                prediction.get('svm', False),
                json.dumps(prediction.get('features', {}))
            ))
            self.connection.commit()
            return cursor.lastrowid
    
    def save_graph_snapshot(self, graph_data: Dict):
        """Save periodic graph snapshot"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO graph_snapshots (
                    timestamp, node_count, edge_count, threat_count, graph_data
                ) VALUES (?, ?, ?, ?, ?)
            ''', (
                int(time.time() * 1000),
                graph_data.get('node_count', 0),
                graph_data.get('edge_count', 0),
                graph_data.get('threat_count', 0),
                json.dumps(graph_data.get('graph', {}))
            ))
            self.connection.commit()
            return cursor.lastrowid
    
    def insert_ai_training_log(self, log_entry: Dict):
        """Insert AI Training Session Log"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO ai_training_logs (
                    timestamp, samples_count, features_count, training_duration,
                    iso_forest_anomalies, svm_anomalies, status, model_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_entry.get('timestamp', int(time.time() * 1000)),
                log_entry.get('samples_count', 0),
                log_entry.get('features_count', 0),
                log_entry.get('training_duration', 0.0),
                log_entry.get('iso_forest_anomalies', 0),
                log_entry.get('svm_anomalies', 0),
                log_entry.get('status', 'unknown'),
                json.dumps(log_entry.get('model_metadata', {}))
            ))
            self.connection.commit()
            return cursor.lastrowid

    def get_ai_training_logs(self, limit: int = 100) -> List[Dict]:
        """Get recent AI training logs"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM ai_training_logs 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    # ================================================================
    # QUERY METHODS
    # ================================================================
    
    def get_threats_by_time_range(self, start_time: int, end_time: int) -> List[Dict]:
        """Get all threats in time range"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM threats 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
            ''', (start_time, end_time))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_threats_by_pid(self, pid: int) -> List[Dict]:
        """Get all threats for a specific PID"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM threats 
                WHERE pid = ?
                ORDER BY timestamp DESC
            ''', (pid,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_recent_threats(self, limit: int = 100) -> List[Dict]:
        """Get most recent threats"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM threats 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_pattern_matches(self, pattern_name: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get pattern matches, optionally filtered by pattern name"""
        with self.lock:
            cursor = self.connection.cursor()
            if pattern_name:
                cursor.execute('''
                    SELECT * FROM pattern_matches 
                    WHERE pattern_name = ?
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (pattern_name, limit))
            else:
                cursor.execute('''
                    SELECT * FROM pattern_matches 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_ai_anomalies(self, limit: int = 100) -> List[Dict]:
        """Get AI-detected anomalies"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM ai_predictions 
                WHERE is_anomaly = 1
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def query_events_by_pid(self, pid: int) -> List[Dict]:
        """Get all events for a specific PID, ordered chronologically"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM events 
                WHERE pid = ?
                ORDER BY timestamp ASC
            ''', (pid,))
            return [dict(row) for row in cursor.fetchall()]
            
    def query_events(self, hours: int = 24, threat_level: Optional[int] = None) -> List[Dict]:
        """Query historical events in the last N hours, optionally filtered by threat level"""
        with self.lock:
            cursor = self.connection.cursor()
            start_timestamp = int((time.time() - (hours * 3600)) * 1000)
            
            if threat_level is not None:
                cursor.execute('''
                    SELECT * FROM events 
                    WHERE timestamp >= ? AND threat_level = ?
                    ORDER BY timestamp DESC
                ''', (start_timestamp, threat_level))
            else:
                cursor.execute('''
                    SELECT * FROM events 
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC
                ''', (start_timestamp,))
            return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict:
        """Get database statistics"""
        with self.lock:
            cursor = self.connection.cursor()
            
            stats = {}
            
            # Total events
            cursor.execute('SELECT COUNT(*) as count FROM events')
            stats['total_events'] = cursor.fetchone()['count']
            
            # Total threats
            cursor.execute('SELECT COUNT(*) as count FROM threats')
            stats['total_threats'] = cursor.fetchone()['count']
            
            # Threats by level
            cursor.execute('SELECT threat_level, COUNT(*) as count FROM threats GROUP BY threat_level')
            stats['threats_by_level'] = {row['threat_level']: row['count'] for row in cursor.fetchall()}
            
            # Pattern matches
            cursor.execute('SELECT COUNT(*) as count FROM pattern_matches')
            stats['total_patterns'] = cursor.fetchone()['count']
            
            # AI anomalies
            cursor.execute('SELECT COUNT(*) as count FROM ai_predictions WHERE is_anomaly = 1')
            stats['ai_anomalies'] = cursor.fetchone()['count']
            
            # Top patterns
            cursor.execute('''
                SELECT pattern_name, COUNT(*) as count 
                FROM pattern_matches 
                GROUP BY pattern_name 
                ORDER BY count DESC 
                LIMIT 5
            ''')
            stats['top_patterns'] = {row['pattern_name']: row['count'] for row in cursor.fetchall()}
            
            return stats
    
    def get_timeline_data(self, hours: int = 24) -> List[Dict]:
        """Get threat timeline for last N hours"""
        with self.lock:
            cutoff_time = int((time.time() - hours * 3600) * 1000)
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT timestamp, threat_level, process_name, ai_anomaly
                FROM threats 
                WHERE timestamp > ?
                ORDER BY timestamp ASC
            ''', (cutoff_time,))
            return [dict(row) for row in cursor.fetchall()]
    
    # ================================================================
    # FORENSIC QUERIES
    # ================================================================
    
    def get_process_history(self, pid: int) -> Dict:
        """Get complete history for a process"""
        with self.lock:
            cursor = self.connection.cursor()
            
            # Get all events
            cursor.execute('SELECT * FROM events WHERE pid = ? ORDER BY timestamp', (pid,))
            events = [dict(row) for row in cursor.fetchall()]
            
            # Get threats
            cursor.execute('SELECT * FROM threats WHERE pid = ? ORDER BY timestamp', (pid,))
            threats = [dict(row) for row in cursor.fetchall()]
            
            # Get patterns
            cursor.execute('SELECT * FROM pattern_matches WHERE pid = ? ORDER BY timestamp', (pid,))
            patterns = [dict(row) for row in cursor.fetchall()]
            
            # Get AI predictions
            cursor.execute('SELECT * FROM ai_predictions WHERE pid = ? ORDER BY timestamp', (pid,))
            ai_preds = [dict(row) for row in cursor.fetchall()]
            
            return {
                'pid': pid,
                'events': events,
                'threats': threats,
                'patterns': patterns,
                'ai_predictions': ai_preds
            }
    
    # ================================================================
    # EXPORT METHODS
    # ================================================================
    
    def export_to_json(self, filepath: str, table: str = 'threats', limit: int = 1000):
        """Export table to JSON file"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute(f'SELECT * FROM {table} ORDER BY timestamp DESC LIMIT ?', (limit,))
            data = [dict(row) for row in cursor.fetchall()]
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"[DB] Exported {len(data)} rows to {filepath}")
    
    def export_to_csv(self, filepath: str, table: str = 'threats', limit: int = 1000):
        """Export table to CSV file"""
        import csv
        
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute(f'SELECT * FROM {table} ORDER BY timestamp DESC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            
            if not rows:
                print(f"[DB] No data to export")
                return
            
            # Get column names
            columns = rows[0].keys()
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=columns)
                writer.writeheader()
                for row in rows:
                    writer.writerow(dict(row))
            
            print(f"[DB] Exported {len(rows)} rows to {filepath}")
    
    # ================================================================
    # MAINTENANCE
    # ================================================================
    
    def cleanup_old_data(self, retention_days: int = 30):
        """Delete data older than retention period"""
        with self.lock:
            cutoff_time = int((time.time() - retention_days * 86400) * 1000)
            cursor = self.connection.cursor()
            
            # Delete old events
            cursor.execute('DELETE FROM events WHERE timestamp < ?', (cutoff_time,))
            deleted_events = cursor.rowcount
            
            # Delete old threats
            cursor.execute('DELETE FROM threats WHERE timestamp < ?', (cutoff_time,))
            deleted_threats = cursor.rowcount
            
            # Delete old patterns
            cursor.execute('DELETE FROM pattern_matches WHERE timestamp < ?', (cutoff_time,))
            deleted_patterns = cursor.rowcount
            
            # Delete old AI predictions
            cursor.execute('DELETE FROM ai_predictions WHERE timestamp < ?', (cutoff_time,))
            deleted_ai = cursor.rowcount
            
            # Delete old snapshots (keep last 100)
            cursor.execute('''
                DELETE FROM graph_snapshots 
                WHERE id NOT IN (
                    SELECT id FROM graph_snapshots 
                    ORDER BY timestamp DESC 
                    LIMIT 100
                )
            ''')
            deleted_snapshots = cursor.rowcount
            
            self.connection.commit()
            
            print(f"[DB] Cleanup complete:")
            print(f"     Events: {deleted_events}")
            print(f"     Threats: {deleted_threats}")
            print(f"     Patterns: {deleted_patterns}")
            print(f"     AI Predictions: {deleted_ai}")
            print(f"     Snapshots: {deleted_snapshots}")
    
    def vacuum(self):
        """Optimize database (reclaim space)"""
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute('VACUUM')
            self.connection.commit()
            print("[DB] Database optimized")
    
    def close(self):
        """Close database connection"""
        with self.lock:
            if self.connection:
                try:
                    self.connection.commit()
                    self.connection.close()
                    print("[DB] Connection closed cleanly")
                except Exception as e:
                    print(f"[DB] Error closing connection: {e}")
                finally:
                    self.connection = None


# ================================================================
# TESTING
# ================================================================

if __name__ == "__main__":
    # Test the database
    print("Testing EventDatabase...")
    
    db = EventDatabase("test_sysoptima.db")
    
    # Insert test event
    test_event = {
        'timestamp': int(time.time() * 1000),
        'event_type': 1,
        'pid': 1234,
        'ppid': 100,
        'name': 'test.exe',
        'full_path': 'C:\\test\\test.exe',
        'threat_level': 0,
        'is_signed': False,
        'origin': 'Internet'
    }
    event_id = db.insert_event(test_event)
    print(f"Inserted event ID: {event_id}")
    
    # Insert test threat
    test_threat = {
        'timestamp': int(time.time() * 1000),
        'pid': 1234,
        'name': 'malware.exe',
        'threat_level': 2,
        'action': 'killed',
        'tags': ['TAG_PERSISTENCE', 'TAG_NETWORK'],
        'mitre': ['T1547', 'T1071'],
        'ai_anomaly': True,
        'ai_confidence': 0.95
    }
    threat_id = db.insert_threat(test_threat)
    print(f"Inserted threat ID: {threat_id}")
    
    # Get stats
    stats = db.get_stats()
    print(f"Stats: {stats}")
    
    # Cleanup
    db.close()
    os.remove("test_sysoptima.db")
    print("Test complete!")
