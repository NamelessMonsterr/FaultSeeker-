from copy import deepcopy
from faultseeker.prompts.forensics.trace_analysis_prompts import TraceAnalysisPrompts
from faultseeker.utils.utils import build_agent, is_function_hash, get_function_calls_to_expand


class TraceAnalyzer:
    def __init__(self, txn_seq, txn_info, model='gpt-4o-mini'):
        self.prompts = TraceAnalysisPrompts()
        self.txn_seq = txn_seq
        self.txn_info = txn_info
        self.max_batch_size = 6
        self.max_depth = 10
        self.address_call_memo = {}
        self.function_call_loc_memo = {}
        self.contract_info = {}
        self.loss_estimation = {}
        self.potential_attacker = {}
        self.potential_victim = {}
        self.function_call_memo = {}
        self.likely_vulnerable_functions = {}
        self.attack_vector_record = ''
        self.memo = []

        self.agent = build_agent('', model)
        self.repeated_patterns = {
            'keys': [],
            'keys_function_only': []
        }
        self.function_calls_to_expand_loc = {
            'flashloan': [],
            'flashloan_callback': [],
            'name_in_hash': []
        }
        self.address_calls_with_created_contract_in_params = []
        self.function_calls_to_expand = get_function_calls_to_expand()
    
    
    @staticmethod
    def find_repeated_patterns(sequence):
        n = len(sequence)
        all_patterns = []
        
        # Try different pattern lengths
        for pattern_len in range(1, n // 2 + 1):
            # Slide through the sequence
            i = 0
            while i <= n - pattern_len * 2:
                pattern = sequence[i:i+pattern_len]
                repeats = 1
                next_pos = i + pattern_len
                
                # Count consecutive repeats
                while (next_pos + pattern_len <= n and 
                    sequence[next_pos:next_pos+pattern_len] == pattern):
                    repeats += 1
                    next_pos += pattern_len
                
                # If we found a repeated pattern
                if repeats > 1:
                    all_patterns.append({
                        "pattern": pattern,
                        "repeats": repeats,
                        "start_index": i,
                        "end_index": next_pos
                    })
                    
                    # Move past this repeated sequence
                    i = next_pos
                else:
                    i += 1
        
        # Sort by start index to maintain sequence order
        all_patterns.sort(key=lambda x: x["start_index"])
        
        # Remove overlapping patterns (prioritize longer patterns)
        non_overlapping = []
        if all_patterns:
            # Sort by total pattern length (pattern_len * repeats) in descending order
            all_patterns.sort(key=lambda x: len(x["pattern"]) * x["repeats"], reverse=True)
            
            used_indices = set()
            for pattern_info in all_patterns:
                start = pattern_info["start_index"]
                end = pattern_info["end_index"]
                
                # Check if this pattern overlaps with any already selected
                overlap = any(i in used_indices for i in range(start, end))
                
                if not overlap:
                    non_overlapping.append(pattern_info)
                    # Mark these indices as used
                    for i in range(start, end):
                        used_indices.add(i)
            
            # Sort back by position for output
            non_overlapping.sort(key=lambda x: x["start_index"])
        
        return non_overlapping

    
    def _update_loop_in_trace(self, todo, repeated_patterns):
        shift = 0
        for pattern in repeated_patterns:
            pattern_length = len(pattern['pattern'])
            pattern_repeats = pattern['repeats']
            pattern_start = pattern['start_index'] - shift
            pattern_end = pattern['end_index'] - shift
            pattern_info = {
                'type': 'loop',
                'number_of_repeats': pattern_repeats,
                'function_calls': pattern['pattern'],
                'function_calls_with_children': todo[pattern_start:(pattern_start + pattern_length)],
            }
            todo = todo[:pattern_start] + [pattern_info] + todo[pattern_end:]
            shift = pattern_length * (pattern_repeats - 1) + 1
        return todo

    def _flatten_trace_single(self, trace, depth):
        output = []
        # Enter frames in preorder; finish sibling-pattern work in the original
        # postorder, without consuming Python's call stack for EVM frame depth.
        pending = [(trace, depth, False)]
        active = set()
        while pending:
            current, current_depth, exiting = pending.pop()
            children = current.get('children', [])
            if exiting:
                self._record_repeated_trace_patterns(children)
                active.remove(id(current))
                continue
            if id(current) in active:
                raise ValueError('Cyclic trace cannot be flattened')
            active.add(id(current))
            output.append(self._flatten_trace_frame(current, current_depth))
            pending.append((current, current_depth, True))
            pending.extend((child, current_depth + [index], False)
                           for index, child in reversed(list(enumerate(children))))
        return output

    def _flatten_trace_frame(self, trace, depth):
        trace['depth'] = depth
        # Descendants are visited separately and never appear in flat records.
        # Copying their whole subtrees here was both recursive and quadratic.
        trace_copy = deepcopy({key: value for key, value in trace.items() if key != 'children'})
        if ('function' in trace_copy) and trace_copy['function']:
            key = trace_copy['address'].lower()
            if key not in self.address_call_memo:
                self.address_call_memo[key] = {}
            if trace_copy['function'] not in self.address_call_memo[key]:
                self.address_call_memo[key][trace_copy['function']] = []
            self.address_call_memo[key][trace_copy['function']].append(trace_copy)
            key_function_call_loc = f"{trace_copy['function']}::{trace_copy['address']}".lower()
            if key_function_call_loc not in self.function_call_loc_memo:
                self.function_call_loc_memo[key_function_call_loc] = []
            self.function_call_loc_memo[key_function_call_loc].append(trace_copy)
            if trace_copy['function'] in self.function_calls_to_expand['flashloan']:
                self.function_calls_to_expand_loc['flashloan'].append(trace_copy)
            elif trace_copy['function'] in self.function_calls_to_expand['callback']:
                self.function_calls_to_expand_loc['flashloan_callback'].append(trace_copy)
            elif is_function_hash(trace_copy['function']):
                self.function_calls_to_expand_loc['name_in_hash'].append(trace_copy)
            elif trace_copy['params'] and self.txn_seq['created_address']:
                for i in self.txn_seq['created_address']:
                    if i in trace_copy['params'].lower():
                        self.address_calls_with_created_contract_in_params.append(trace_copy)  
        return trace_copy

    def _record_repeated_trace_patterns(self, todo):
        if len(todo) > 3:
            keys = [] 
            keys_function_only = []
            for i in todo:
                if 'function' not in i:
                    keys.append('')
                    keys_function_only.append('')
                # if (i['type'] in ['call', 'delegatecall']) and (i['type'] not in ['staticcall', 'return']) and (i['call_type'] not in ['staticcall', 'return']):
                else:
                    keys.append(f'{i["address"]}::{i["function"]}::{i["params"]}')
                    keys_function_only.append(i["function"])
            repeated_patterns_keys = self.find_repeated_patterns(keys)
            repeated_patterns_keys_function = self.find_repeated_patterns(keys_function_only)
            if repeated_patterns_keys:
                # todo = self._update_loop_in_trace(todo, repeated_patterns_keys)
                for repeated_single in repeated_patterns_keys:
                    pattern = [deepcopy({key: value for key, value in node.items() if key != 'children'})
                               for node in todo[repeated_single['start_index']:repeated_single['start_index']+len(repeated_single['pattern'])]]
                    repeated_single['pattern'] = pattern
                self.repeated_patterns['keys'].extend(repeated_patterns_keys)
            if repeated_patterns_keys_function:
                for repeated_single in repeated_patterns_keys_function:
                    pattern = [deepcopy({key: value for key, value in node.items() if key != 'children'})
                               for node in todo[repeated_single['start_index']:repeated_single['start_index']+len(repeated_single['pattern'])]]
                    repeated_single['pattern'] = pattern
                self.repeated_patterns['keys_function_only'].extend(repeated_patterns_keys_function)
    
    def _flatten_trace(self):
        output = []
        trace = self.txn_seq['trace']
        if isinstance(trace, dict):
            self.trace = [trace]
        for i,t in enumerate(self.trace):
            output.extend(self._flatten_trace_single(t, [i]))
        self.trace = trace
        return output
    
    
    def run(self):
        if self.txn_seq:
            self.flatten_trace = self._flatten_trace()
            result = {
                'transaction_hash': self.txn_seq['transaction_hash'],
                'chain': self.txn_seq['chain'],
                'trace': self.trace,
                'canonical_trace': self.txn_seq.get('canonical_trace'),
                'storage_events': self.txn_seq.get('storage_events', []),
                'trace_state_diff': self.txn_seq.get('trace_state_diff', {}),
                'address_relation': self.txn_seq['address_relation'],
                'address_calls': self.address_call_memo,
                'created_address': self.txn_seq['created_address'],
                'repeated_patterns': self.repeated_patterns,
                'function_calls_to_expand_loc': self.function_calls_to_expand_loc,
                'address_calls_with_created_contract_in_params': self.address_calls_with_created_contract_in_params,
                'flatten_trace': self.flatten_trace,
                'function_call_loc_memo': self.function_call_loc_memo,
            }
            return result
        return {}
