"""
SysOptima Lineage Tracker
Traverses process directed graphs to analyze child-parent spawns and extract contextual scores.
"""
import os
import re
from typing import Dict, List, Optional, Set
import networkx as nx

class LineageTracker:
    """Calculates ancestry hierarchies, tree depths, and graph threat context flags"""
    
    SUSPICIOUS_PATHS = re.compile(r'\\(temp|appdata|downloads|users\\public)\\', re.I)
    
    @staticmethod
    def find_latest_node_by_pid(G: nx.DiGraph, pid: int) -> Optional[str]:
        """Find the latest process node ID in the graph matching a raw PID"""
        candidates = [
            (n, G.nodes[n]['timestamp']) 
            for n in G.nodes() 
            if G.nodes[n].get('pid') == pid and G.nodes[n].get('node_type') == 'process'
        ]
        if candidates:
            return max(candidates, key=lambda x: x[1])[0]
        return None

    @staticmethod
    def get_process_lineage(G: nx.DiGraph, node_id: str) -> Dict:
        """
        Get the full process tree ancestry and descendants for a target process node ID.
        """
        if node_id not in G:
            return {'ancestors': [], 'descendants': [], 'process': None}
            
        process_data = G.nodes[node_id]
        
        # Get ancestors
        ancestors = []
        current = node_id
        while current:
            parents = list(G.predecessors(current))
            if parents:
                current = parents[0]
                if G.nodes[current].get('node_type') == 'process':
                    ancestors.append({
                        'node_id': current,
                        'pid': G.nodes[current].get('pid'),
                        **G.nodes[current]
                    })
                else:
                    break
            else:
                break
                
        # Get descendants
        descendants = []
        stack = [node_id]
        visited = set()
        
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            
            for child in G.successors(current):
                if G.nodes[child].get('node_type') == 'process':
                    descendants.append({
                        'node_id': child,
                        'pid': G.nodes[child].get('pid'),
                        **G.nodes[child]
                    })
                    stack.append(child)
                    
        return {
            'process': {'node_id': node_id, 'pid': process_data.get('pid'), **process_data},
            'ancestors': ancestors,
            'descendants': descendants
        }

    @classmethod
    def calculate_tree_depth(cls, G: nx.DiGraph, node_id: str) -> int:
        """Calculate ancestry tree depth (spawning level) for a process node"""
        depth = 0
        current = node_id
        while current:
            parents = list(G.predecessors(current))
            if parents and G.nodes[parents[0]].get('node_type') == 'process':
                depth += 1
                current = parents[0]
            else:
                break
        return depth

    @classmethod
    def calculate_suspicious_parent_flag(cls, G: nx.DiGraph, node_id: str) -> int:
        """
        Return 1 if any parent/ancestor in the process lineage has suspicious properties, else 0.
        """
        lineage = cls.get_process_lineage(G, node_id)
        for ancestor in lineage['ancestors']:
            if not ancestor.get('is_signed', True):
                return 1
            if ancestor.get('threat', 0) >= 2:
                return 1
            full_path = ancestor.get('full_path', '')
            if full_path and cls.SUSPICIOUS_PATHS.search(full_path):
                return 1
        return 0

    @classmethod
    def calculate_lineage_threat_score(cls, G: nx.DiGraph, node_id: str) -> float:
        """
        Accumulates the threat score of all process ancestors to evaluate context.
        """
        lineage = cls.get_process_lineage(G, node_id)
        score = 0.0
        for ancestor in lineage['ancestors']:
            threat = ancestor.get('threat', 0)
            if threat >= 2:
                score += 50.0
            elif threat >= 1:
                score += 20.0
            else:
                score += 5.0
        return score
