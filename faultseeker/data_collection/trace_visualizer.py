import re
import networkx as nx
import matplotlib
matplotlib.use('Agg')   # Non-interactive backend — prevents Tkinter thread crash
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from faultseeker.data_collection.trace_parser import TraceNode



class TraceGraphGenerator:
    def generate(self, root):
        if isinstance(root, dict):
            root = TraceNode.from_dict(root)
            
        lines = []
        self._generate_node(lines, root, ancestors=[], is_last=True)
        return '\n'.join(lines)
    
    def _generate_node(self, lines, node, ancestors, is_last):
        stack = [(node, ancestors, is_last, False)]
        active = set()
        while stack:
            current, current_ancestors, current_last, exiting = stack.pop()
            if exiting:
                active.remove(id(current))
                continue
            if id(current) in active:
                raise ValueError('Cyclic trace node')
            active.add(id(current))
            stack.append((current, current_ancestors, current_last, True))
            lines.append(self._format_node_line(current, current_ancestors, current_last))
            if current.type == 'call':
                children = list(current.children)
                for i in range(len(children) - 1, -1, -1):
                    stack.append((children[i], current_ancestors + [not current_last],
                                  i == len(children) - 1, False))
    
    def _build_prefix(self, ancestors, is_last):
        prefix = ''
        for has_sibling_after in ancestors:
            if has_sibling_after:
                prefix += '│   '
            else:
                prefix += '    '
        if ancestors:
            prefix += '└─ ' if is_last else '├─ '
        return prefix
    
    def _format_node_line(self, node, ancestors, is_last):
        prefix = self._build_prefix(ancestors, is_last)
        
        if node.type == 'call':
            parts = [f"[{node.gas}] {node.address}::{node.function}({node.params or ''})"]
            if node.call_type:
                parts.append(f" [{node.call_type}]")
            line = ''.join(parts)
        elif node.type == 'create':
            contract_type = node.function.replace('new ', '')
            line = f"[{node.gas}] → new {contract_type}@{node.address}"
        elif node.type == 'return':
            line = f"← [Return] {node.value}"
        else:
            line = 'Unknown node type'
            
        return prefix + line


class TransactionTraceVisualizer:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.address_call_memo = {}
        self.call_types = {
            "delegatecall": "orange",
            "staticcall": "blue",
            "call": "green",
            "create": "red"
        }
        self.node_counter = 0
    
    def build_graph_from_tree(self, root_node):
        if isinstance(root_node, dict):
            root_node = TraceNode.from_dict(root_node)
            
        self.graph.clear()
        self.node_counter = 0
        self._add_node_to_graph(root_node, parent_id=None, level=0)
    
    def _add_node_to_graph(self, node, parent_id, level):
        root_id = None
        stack = [(node, parent_id, level, False)]
        active = set()
        while stack:
            current, current_parent, current_level, exiting = stack.pop()
            if exiting:
                active.remove(id(current))
                continue
            if current.type not in ('call', 'create'):
                continue
            if id(current) in active:
                raise ValueError('Cyclic trace node')
            active.add(id(current))
            stack.append((current, current_parent, current_level, True))
            node_id = f"node_{self.node_counter}"
            self.node_counter += 1
            if root_id is None:
                root_id = node_id
            if current.type == 'create':
                details = f"new {current.function.replace('new ', '')}@{current.address}"
                call_type = 'create'
            else:
                details = f"{current.address}::{current.function}({current.params or ''})"
                call_type = current.call_type or 'call'
            self.graph.add_node(node_id, details=details, gas_cost=current.gas,
                                call_type=call_type, level=current_level, params=current.params,
                                address=current.address, function=current.function, node_type=current.type)
            if current_parent:
                self.graph.add_edge(current_parent, node_id, call_type=call_type)
            for child in reversed(list(current.children)):
                if child.type in ('call', 'create'):
                    stack.append((child, node_id, current_level + 1, False))
        return root_id
    
    def _convert_networkx_graph_to_png(self, graph, output_path, node_size=300, node_color='skyblue', edge_color='black', font_size=10, with_labels=True, layout=nx.spring_layout):
        plt.figure(figsize=(16, 12), dpi=150)
        if layout is None:
            pos = nx.kamada_kawai_layout(graph, scale=2.0)
        else:
            pos = layout(graph)
        nx.draw_networkx_nodes(
            graph, 
            pos=pos,
            node_size=node_size,
            node_color=node_color,
        )
        nx.draw_networkx_labels(
            graph, 
            pos=pos,
            font_size=font_size,
            font_weight='bold'
        )
        edge_list = list(graph.edges())
        nx.draw_networkx_edges(
            graph, 
            pos=pos,
            edgelist=edge_list,
            edge_color=edge_color,
            arrows=True,  
            arrowsize=20,  
            width=1.5,
            connectionstyle='arc3,rad=0.1'  
        )
        edge_labels = nx.get_edge_attributes(graph, 'label')
        nx.draw_networkx_edge_labels(
            graph, 
            pos=pos,
            edge_labels=edge_labels,
            font_size=font_size,
            font_color='red',
            label_pos=0.5,
            bbox=dict(facecolor='white', edgecolor='none', alpha=0.7, pad=3)
        )
        plt.axis('off')
        plt.savefig(output_path, format='png', dpi=300, bbox_inches='tight', transparent=False)
        plt.close()
    
    def draw_address_relation(self):
        graph = nx.DiGraph()
        for _, data in self.graph.nodes(data=True):
            if data['params']:
                address_in_params = set(re.findall(r'0x[a-fA-F0-9]{40}',data['params']))
                for addr in address_in_params:
                    graph.add_edge(data['address'].lower(), addr.lower(), label=f"{data['call_type']} ({data['function']})")
        return nx.node_link_data(graph,edges='edges')
    
    def draw_graph(self, figsize=(12, 10)):
        plt.figure(figsize=figsize)
        try:
            pos = nx.nx_agraph.graphviz_layout(self.graph, prog="dot")
        except Exception:
            pos = nx.spring_layout(self.graph, k=0.5, iterations=50)
            for node, data in self.graph.nodes(data=True):
                level = data.get('level', 0)
                pos[node][1] = 1.0 - (level * 0.1)
        call_types = set(nx.get_edge_attributes(self.graph, 'call_type').values())
        for call_type in call_types:
            edge_list = [(u, v) for u, v, d in self.graph.edges(data=True) if d.get('call_type') == call_type]
            nx.draw_networkx_edges(
                self.graph, pos, 
                edgelist=edge_list, 
                width=1.5, 
                edge_color=self.call_types.get(call_type, 'black'),
                arrows=True,
                arrowsize=15
            )
        nx.draw_networkx_nodes(
            self.graph, pos,
            node_size=2000,
            node_color='lightgray',
            edgecolors='black',
            linewidths=1.0
        )
        labels = {}
        for node, data in self.graph.nodes(data=True):
            addr = data.get('address', '')
            if addr:
                func = data.get('function', '')
                labels[node] = f"{addr}::{func}"
            else:
                labels[node] = data.get('details', '')[:30] 
        
        nx.draw_networkx_labels(
            self.graph, pos,
            labels=labels,
            font_size=9,
            font_family='monospace'
        )
        legend_elements = [
            Line2D([0], [0], color=color, lw=2, label=call_type)
            for call_type, color in self.call_types.items()
        ]        
        plt.legend(handles=legend_elements, loc='upper right')
        plt.axis('off')
        plt.tight_layout()
        return plt
    
    def save_graph(self, filename="transaction_trace_graph.png"):
        plt = self.draw_graph()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        # print(f"Graph saved to {filename}")
    
    def display_gas_summary(self):
        print("\nGas Usage Summary:")
        print("-" * 80)
        print(f"{'Node':<10} {'Gas Cost':<12} {'Call Type':<15} {'Transaction'}")
        print("-" * 80)
        
        for node, data in sorted(self.graph.nodes(data=True), key=lambda x: x[1].get('gas_cost', 0), reverse=True):
            gas_cost = data.get('gas_cost', 'N/A')
            if gas_cost != 'N/A':
                gas_cost = f"{gas_cost:,}"
            call_type = data.get('call_type', 'call')
            details = data.get('details', '')
            print(f"{node:<10} {gas_cost:<12} {call_type:<15} {details[:50]}")
        total_gas = sum(data.get('gas_cost', 0) for _, data in self.graph.nodes(data=True))
        print("-" * 80)
        print(f"Total Gas: {total_gas:,}")
