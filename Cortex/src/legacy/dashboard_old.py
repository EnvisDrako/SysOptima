"""
SysOptima Production Dashboard
Interactive web-based UI with real-time threat monitoring using Plotly Dash
"""

import dash
from dash import dcc, html, Input, Output, State, dash_table
import plotly.graph_objs as go
import plotly.express as px
from datetime import datetime, timedelta
import time
import threading
import pandas as pd
import networkx as nx
from collections import defaultdict

# Import SysOptima components
from database import EventDatabase


class SysOptimaDashboard:
    """Interactive Dash dashboard for SysOptima EDR"""
    
    def __init__(self, threat_graph, ai_observer, db: EventDatabase):
        self.graph = threat_graph
        self.ai = ai_observer
        self.db = db
        
        # Create Dash app
        self.app = dash.Dash(__name__, suppress_callback_exceptions=True)
        self.app.title = "SysOptima EDR Dashboard"
        
        # Setup layout
        self.setup_layout()
        self.setup_callbacks()
    
    def setup_layout(self):
        """Create dashboard layout"""
        self.app.layout = html.Div([
            # Header
            html.Div([
                html.H1("🛡️ SysOptima EDR Dashboard", style={'color': 'white', 'marginBottom': 0}),
                html.P("Real-time Threat Detection & Response", style={'color': '#bbb'}),
            ], style={
                'backgroundColor': '#2c3e50',
                'padding': '20px',
                'marginBottom': '20px'
            }),
            
            # Stats Cards Row
            html.Div([
                self.create_stat_card("Total Processes", "total-processes", "🔄"),
                self.create_stat_card("Threats Detected", "threats-detected", "⚠️"),
                self.create_stat_card("AI Anomalies", "ai-anomalies", "🤖"),
                self.create_stat_card("Patterns Matched", "patterns-matched", "🎯"),
            ], style={'display': 'flex', 'gap': '20px', 'marginBottom': '20px'}),
            
            # Main Content Grid
            html.Div([
                # Left Column - Threat Graph
                html.Div([
                    html.H3("🌐 Live Threat Graph", style={'color': '#34495e'}),
                    dcc.Graph(id='threat-graph', style={'height': '500px'})
                ], style={'flex': '2', 'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '10px', 'marginRight': '20px'}),
                
                # Right Column - Threat Log
                html.Div([
                    html.H3("📋 Recent Threats", style={'color': '#34495e'}),
                    html.Div(id='threat-log', style={'height': '500px', 'overflowY': 'scroll'})
                ], style={'flex': '1', 'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '10px'}),
            ], style={'display': 'flex', 'marginBottom': '20px'}),
            
            # Bottom Row
            html.Div([
                # Timeline
                html.Div([
                    html.H3("📊 Threat Timeline (24h)", style={'color': '#34495e'}),
                    dcc.Graph(id='threat-timeline', style={'height': '250px'})
                ], style={'flex': '1', 'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '10px', 'marginRight': '20px'}),
                
                # AI Status
                html.Div([
                    html.H3("🤖 AI Observer Status", style={'color': '#34495e'}),
                    html.Div(id='ai-status')
                ], style={'flex': '1', 'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '10px'}),
            ], style={'display': 'flex', 'marginBottom': '20px'}),
            
            # Pattern Matches Table
            html.Div([
                html.H3("🎯 Attack Pattern Matches", style={'color': '#34495e'}),
                html.Div(id='pattern-table')
            ], style={'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '10px'}),
            
            # Auto-refresh interval
            dcc.Interval(
                id='interval-component',
                interval=2*1000,  # Update every 2 seconds
                n_intervals=0
            )
        ], style={
            'backgroundColor': '#ecf0f1',
            'padding': '20px',
            'fontFamily': 'Arial, sans-serif'
        })
    
    def create_stat_card(self, title, id_name, icon):
        """Create a statistics card"""
        return html.Div([
            html.Div(icon, style={'fontSize': '40px', 'marginBottom': '10px'}),
            html.Div(id=id_name, children="0", style={'fontSize': '32px', 'fontWeight': 'bold', 'color': '#2c3e50'}),
            html.Div(title, style={'color': '#7f8c8d', 'fontSize': '14px'})
        ], style={
            'flex': '1',
            'backgroundColor': 'white',
            'padding': '20px',
            'borderRadius': '10px',
            'textAlign': 'center',
            'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'
        })
    
    def setup_callbacks(self):
        """Setup all dashboard callbacks"""
        
        @self.app.callback(
            [
                Output('total-processes', 'children'),
                Output('threats-detected', 'children'),
                Output('ai-anomalies', 'children'),
                Output('patterns-matched', 'children'),
                Output('threat-graph', 'figure'),
                Output('threat-log', 'children'),
                Output('threat-timeline', 'figure'),
                Output('ai-status', 'children'),
                Output('pattern-table', 'children'),
            ],
            [Input('interval-component', 'n_intervals')]
        )
        def update_dashboard(n):
            """Update all dashboard components"""
            
            # Get database stats
            db_stats = self.db.get_stats()
            
            # Get graph data
            G_snap, graph_stats, history, patterns = self.graph.get_visualization_data()
            
            # 1. Update stats cards
            total_procs = graph_stats.get('total_processes', 0)
            total_threats = db_stats.get('total_threats', 0)
            ai_anomalies = db_stats.get('ai_anomalies', 0)
            pattern_count = db_stats.get('total_patterns', 0)
            
            # 2. Create threat graph
            graph_fig = self.create_threat_graph(G_snap)
            
            # 3. Create threat log
            recent_threats = self.db.get_recent_threats(limit=20)
            threat_log = self.create_threat_log(recent_threats)
            
            # 4. Create timeline
            timeline_fig = self.create_timeline(history)
            
            # 5. AI status
            ai_status_div = self.create_ai_status()
            
            # 6. Pattern table
            pattern_table = self.create_pattern_table(patterns)
            
            return (
                f"{total_procs:,}",
                f"{total_threats:,}",
                f"{ai_anomalies:,}",
                f"{pattern_count:,}",
                graph_fig,
                threat_log,
                timeline_fig,
                ai_status_div,
                pattern_table
            )
    
    def create_threat_graph(self, G):
        """Create interactive threat graph"""
        if G.number_of_nodes() == 0:
            # Empty graph
            fig = go.Figure()
            fig.add_annotation(
                text="No threats detected<br>(All systems normal)",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=20, color="green")
            )
            fig.update_layout(
                xaxis=dict(visible=False),
                yaxis=dict(visible=False),
                plot_bgcolor='white',
                height=500
            )
            return fig
        
        # Filter to threat nodes only
        threat_nodes = [n for n in G.nodes() if G.nodes[n].get('threat', 0) > 0]
        if not threat_nodes:
            fig = go.Figure()
            fig.add_annotation(
                text="No active threats",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16, color="green")
            )
            fig.update_layout(
                xaxis=dict(visible=False),
                yaxis=dict(visible=False),
                plot_bgcolor='white',
                height=500
            )
            return fig
        
        # Create subgraph
        G_threat = G.subgraph(threat_nodes)
        
        # Layout
        pos = nx.spring_layout(G_threat, k=0.5, iterations=50)
        
        # Create edges
        edge_x = []
        edge_y = []
        for edge in G_threat.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines'
        )
        
        # Create nodes
        node_x = []
        node_y = []
        node_color = []
        node_text = []
        node_size = []
        
        threat_colors = {
            0: '#2ecc71',  # Green
            1: '#f39c12',  # Orange
            2: '#e74c3c',  # Red
        }
        
        for node in G_threat.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            threat = G_threat.nodes[node].get('threat', 0)
            name = G_threat.nodes[node].get('label', 'unknown')
            pid = G_threat.nodes[node].get('pid', 0)
            tags = G_threat.nodes[node].get('tags', [])
            
            node_color.append(threat_colors.get(threat, 'gray'))
            node_text.append(f"{name}<br>PID: {pid}<br>Threat: {threat}<br>Tags: {len(tags)}")
            node_size.append(20 if threat < 2 else 30)
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers',
            hoverinfo='text',
            text=node_text,
            marker=dict(
                size=node_size,
                color=node_color,
                line_width=2
            )
        )
        
        # Create figure
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=0,l=0,r=0,t=0),
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           plot_bgcolor='white',
                           height=500
                       ))
        
        return fig
    
    def create_threat_log(self, threats):
        """Create scrolling threat log"""
        if not threats:
            return html.Div("No threats recorded", style={'color': '#7f8c8d', 'padding': '20px'})
        
        items = []
        for threat in threats:
            timestamp = datetime.fromtimestamp(threat['timestamp'] / 1000).strftime('%H:%M:%S')
            threat_level = threat['threat_level']
            
            color_map = {
                0: '#2ecc71',
                1: '#f39c12',
                2: '#e74c3c'
            }
            
            items.append(html.Div([
                html.Div(timestamp, style={'fontSize': '12px', 'color': '#7f8c8d'}),
                html.Div(threat['process_name'], style={'fontWeight': 'bold', 'color': color_map.get(threat_level, 'gray')}),
                html.Div(f"PID {threat['pid']} • Level {threat_level} • {threat['action_taken']}", 
                        style={'fontSize': '12px', 'color': '#95a5a6'}),
            ], style={
                'borderBottom': '1px solid #ecf0f1',
                'padding': '10px',
                'marginBottom': '10px'
            }))
        
        return html.Div(items)
    
    def create_timeline(self, history):
        """Create threat timeline chart"""
        if not history:
            fig = go.Figure()
            fig.add_annotation(
                text="No data yet",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
            fig.update_layout(height=250)
            return fig
        
        times = [h['time'] - history[0]['time'] for h in history]
        threats = [h['threat'] for h in history]
        
        color_map = {0: '#2ecc71', 1: '#f39c12', 2: '#e74c3c'}
        colors = [color_map.get(t, 'gray') for t in threats]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=times,
            y=threats,
            mode='markers',
            marker=dict(size=10, color=colors),
            hovertemplate='Time: %{x:.1f}s<br>Threat: %{y}<extra></extra>'
        ))
        
        fig.update_layout(
            yaxis=dict(
                tickmode='array',
                tickvals=[0, 1, 2],
                ticktext=['Safe', 'Suspicious', 'Danger']
            ),
            xaxis_title="Time (seconds ago)",
            height=250,
            margin=dict(l=50, r=20, t=20, b=40),
            plot_bgcolor='#f8f9fa'
        )
        
        return fig
    
    def create_ai_status(self):
        """Create AI status panel"""
        if self.ai.is_trained:
            status_color = 'green'
            status_text = "✅ TRAINED & ACTIVE"
            details = f"""
            Samples: {len(self.ai.training_data):,}
            Baseline Mean File Writes: {self.ai.baseline_stats.get('mean_file_writes', 0):.1f}
            Status: Detection Mode
            """
        elif self.ai.is_training:
            status_color = 'orange'
            status_text = "⏳ TRAINING IN PROGRESS"
            progress = len(self.ai.training_data) / 1000 * 100
            details = f"""
            Progress: {progress:.1f}%
            Samples: {len(self.ai.training_data)}/1000
            """
        else:
            status_color = 'red'
            status_text = "❌ NOT TRAINED"
            details = "Press 'T' in console to start training"
        
        return html.Div([
            html.Div(status_text, style={'fontSize': '18px', 'fontWeight': 'bold', 'color': status_color, 'marginBottom': '10px'}),
            html.Pre(details, style={'fontSize': '12px', 'color': '#7f8c8d'})
        ])
    
    def create_pattern_table(self, patterns):
        """Create pattern matches table"""
        if not patterns:
            return html.Div("No patterns detected", style={'color': '#7f8c8d', 'padding': '20px'})
        
        recent = patterns[-10:] if len(patterns) > 10 else patterns
        
        df = pd.DataFrame([
            {
                'Time': datetime.fromtimestamp(p['time'].timestamp()).strftime('%H:%M:%S'),
                'Pattern': p['pattern'],
                'Process': p['name'],
                'PID': p['pid']
            }
            for p in reversed(recent)
        ])
        
        return dash_table.DataTable(
            data=df.to_dict('records'),
            columns=[{'name': i, 'id': i} for i in df.columns],
            style_cell={'textAlign': 'left', 'padding': '10px'},
            style_header={'backgroundColor': '#34495e', 'color': 'white', 'fontWeight': 'bold'},
            style_data={'backgroundColor': 'white'},
            style_data_conditional=[
                {
                    'if': {'row_index': 'odd'},
                    'backgroundColor': '#f8f9fa'
                }
            ]
        )
    
    def run(self, debug=False, port=8050):
        """Run the dashboard server"""
        print(f"\n🌐 Dashboard starting at http://localhost:{port}")
        print(f"   Open this URL in your browser to view the dashboard")
        print(f"   Press Ctrl+C to stop\n")
        self.app.run_server(debug=debug, port=port, host='0.0.0.0')


# ================================================================
# STANDALONE TESTING
# ================================================================

if __name__ == "__main__":
    # Mock objects for testing
    class MockGraph:
        def get_visualization_data(self):
            G = nx.DiGraph()
            stats = {'total_processes': 42}
            history = []
            patterns = []
            return G, stats, history, patterns
    
    class MockAI:
        is_trained = False
        is_training = False
        training_data = []
        baseline_stats = {}
    
    db = EventDatabase("test_dashboard.db")
    graph = MockGraph()
    ai = MockAI()
    
    dashboard = SysOptimaDashboard(graph, ai, db)
    dashboard.run(debug=True)
