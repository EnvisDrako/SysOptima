"""
Utility functions for SysOptima Cortex
"""

import time
from datetime import datetime
from typing import Dict, List


def timestamp_to_datetime(ts: int) -> datetime:
    """Convert millisecond timestamp to datetime"""
    return datetime.fromtimestamp(ts / 1000)


def format_timestamp(ts: int) -> str:
    """Format timestamp for display"""
    dt = timestamp_to_datetime(ts)
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def get_threat_level_name(level: int) -> str:
    """Get human-readable threat level name"""
    names = {
        0: 'Safe',
        1: 'Suspicious',
        2: 'Critical'
    }
    return names.get(level, 'Unknown')


def get_threat_color(level: int) -> str:
    """Get color for threat level"""
    colors = {
        0: '#2ecc71',  # Green
        1: '#f39c12',  # Orange
        2: '#e74c3c',  # Red
    }
    return colors.get(level, '#95a5a6')  # Gray


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def truncate_path(path: str, max_length: int = 50) -> str:
    """Truncate long paths for display"""
    if len(path) <= max_length:
        return path
    return "..." + path[-(max_length-3):]


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (for detecting packed/encrypted files)"""
    if not data:
        return 0.0
    
    import math
    from collections import Counter
    
    # Count byte frequencies
    counts = Counter(data)
    total = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    
    return entropy


def mitre_technique_url(technique_id: str) -> str:
    """Get MITRE ATT&CK technique URL"""
    return f"https://attack.mitre.org/techniques/{technique_id}/"


def format_mitre_list(techniques: List[str]) -> str:
    """Format MITRE technique list for display"""
    if not techniques:
        return "None"
    return ", ".join(techniques)
