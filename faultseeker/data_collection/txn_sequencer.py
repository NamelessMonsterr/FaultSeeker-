import json
from faultseeker.data_collection.txn_replayer import TransactionReplayer
from faultseeker.data_collection.trace_parser import TraceParser, TraceNode
from faultseeker.data_collection.trace_visualizer import TraceGraphGenerator, TransactionTraceVisualizer


class TransactionSequencer:
    def __init__(self):
        self.replayer = TransactionReplayer()
        self.parser = TraceParser()
        self.generator = TraceGraphGenerator()
        self.visualizer = TransactionTraceVisualizer()
    
    def analyze_trace(self, trace_text, depth_limit=1000):
        root_node = self.parser.parse(trace_text,depth_limit)
        if root_node:
            self.visualizer.build_graph_from_tree(root_node)
        return root_node.to_dict() if root_node else None

    @staticmethod
    def _canonical_to_legacy_trace(node: dict) -> dict:
        """Convert canonical RPC trace nodes into the legacy parser-like schema."""
        if not node:
            return {}

        def fields(source):
            if not source:
                return {}
            return {
                'type': 'call', 'gas': source.get('gas'), 'address': source.get('callee'),
                'function': source.get('function_selector'),
                'params': source.get('input', '0x')[10:] if source.get('input') else '',
                'call_type': (source.get('call_type') or '').lower() or None,
                'value': source.get('value'), 'contract_type': None, 'children': [],
            }
        result = fields(node)
        stack = [(node, result, False)]
        active = set()
        while stack:
            source, target, exiting = stack.pop()
            if exiting:
                active.remove(id(source))
                continue
            if not source:
                continue
            if id(source) in active:
                raise ValueError('Cyclic canonical trace')
            active.add(id(source))
            stack.append((source, target, True))
            children = [(child, fields(child), False) for child in source.get('children', [])]
            target['children'] = [child_target for _, child_target, _ in children]
            stack.extend(reversed(children))
        return result
    
    def generate_text_representation(self, root_node):
        return self.generator.generate(root_node)
    
    def visualize_trace(self, figsize=(12, 10)):
        return self.visualizer.draw_graph(figsize=figsize)
    
    def visualize_address_relation(self):
        return self.visualizer.draw_address_relation()
    
    def save_visualization(self, filename="transaction_trace_graph.png"):
        self.visualizer.save_graph(filename)
    
    def display_gas_summary(self):
        self.visualizer.display_gas_summary()
    
    def export_to_json(self, root_node, filename="transaction_trace.json"):
        if isinstance(root_node, TraceNode):
            root_node = root_node.to_dict()
            
        with open(filename, 'w') as f:
            json.dump(root_node, f, indent=2)
    
    def run(self, txn_hash: str, chain: str) -> dict:
        """
        Analyze transaction sequence for given transaction hash and chain.

        Args:
            txn_hash: Transaction hash
            chain: Chain identifier (eth, bsc, poly, etc.)

        Returns:
            Dictionary containing transaction sequence analysis results
        """
        # Prefer the structured trace path for canonical call/state metadata.
        structured_trace = self.replayer.get_structured_trace(txn_hash, chain)

        # Get cast-style trace text from replayer (uses cache internally)
        trace_text = self.replayer.run(txn_hash, chain)
        if not trace_text and not structured_trace:
            return {}

        # Analyze trace
        root_node = self.analyze_trace(trace_text) if trace_text else None
        if not root_node and structured_trace and structured_trace.get('trace'):
            root_node = self._canonical_to_legacy_trace(structured_trace['trace'])
            self.visualizer.build_graph_from_tree(TraceNode.from_dict(root_node))
        if not root_node:
            return {}

        # Build result
        address_relation = self.visualize_address_relation()
        result = {
            "transaction_hash": txn_hash,
            "chain": chain,
            "trace": root_node,
            "canonical_trace": structured_trace.get('trace') if structured_trace else None,
            "storage_events": structured_trace.get('storage_events', []) if structured_trace else [],
            "trace_state_diff": structured_trace.get('state_diff', {}) if structured_trace else {},
            "address_relation": address_relation,
            "address_calls": self.parser.address_call_memo,
            "created_address": self.parser.created_address,
        }

        return result

