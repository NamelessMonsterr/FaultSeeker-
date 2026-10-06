import json
import logging
import networkx as nx
from copy import deepcopy
import time
from faultseeker.data_collection.contract_downloader import ContractDownloader
from faultseeker.function_analysis.function_ranker import RankingResult
from faultseeker.prompts.function_analysis import (
    OrchestrationSessionPrompts,
    TaskCoordinatorPrompts,
    WorkerPrompts,
    VulnerabilityAnalysisPrompts,
    LocalTaskPrompts,
)
from faultseeker.prompts.local_model_prompts import get_worker_prompts, get_vuln_prompts
from faultseeker.utils.utils import build_agent
from faultseeker.core.llm_router import HybridLLMRouter, build_routed_agent
from faultseeker.forensics.result import extract_reentrancy_analysis, compute_priority_breakdown
from faultseeker.research.cost_tracker import CostTracker
from contextlib import nullcontext
from typing import Optional


class FunctionAnalyzer:

    def __init__(self,
                 model='gpt-4o-mini',
                 router: Optional[HybridLLMRouter] = None,
                 cost_tracker: Optional[CostTracker] = None):
        self.txn_analyzer_model = model
        self.router = router
        self.cost_tracker = cost_tracker

        # Prompt selection: always use the LOCAL model name to pick prompt complexity.
        # In hybrid mode, `model` might be 'gemini-2.0-flash' (Stage 2) but agents
        # still run phi3:mini for Tier 1/2 — we must load simplified prompts for those.
        prompt_model = model
        if router and hasattr(router, 'local_model') and router.local_model:
            prompt_model = router.local_model  # e.g. 'phi3:mini'

        self.session_prompts = OrchestrationSessionPrompts()
        self.task_prompts = TaskCoordinatorPrompts()
        self.function_prompts = get_worker_prompts(prompt_model)      # local-aware
        self.vulnerability_prompts = get_vuln_prompts(prompt_model)   # local-aware
        self.local_task_prompts = LocalTaskPrompts()

        # Initialize agents — use routed agent builder when router is provided
        self.reasoning_agent = build_routed_agent(self.session_prompts.function_call_reasoning_init, router=self.router, agent_role='reasoning_agent', system_prompt=self.session_prompts.function_call_reasoning_init) if router else build_agent(self.session_prompts.function_call_reasoning_init, model)
        self.generation_agent = build_routed_agent(self.session_prompts.function_call_task_generation_init, router=self.router, agent_role='generation_agent', system_prompt=self.session_prompts.function_call_task_generation_init) if router else build_agent(self.session_prompts.function_call_task_generation_init, model)
        self.processing_agent = build_routed_agent(self.session_prompts.function_call_info_processing_init, router=self.router, agent_role='processing_agent', system_prompt=self.session_prompts.function_call_info_processing_init) if router else build_agent(self.session_prompts.function_call_info_processing_init, model)
        self.organization_agent = build_routed_agent(self.session_prompts.function_call_organization_init, router=self.router, agent_role='organization_agent', system_prompt=self.session_prompts.function_call_organization_init) if router else build_agent(self.session_prompts.function_call_organization_init, model)
        self.children_call_filtering_agent = build_routed_agent(self.session_prompts.function_call_children_call_filtering_init, router=self.router, agent_role='children_call_filtering', system_prompt=self.session_prompts.function_call_children_call_filtering_init) if router else build_agent(self.session_prompts.function_call_children_call_filtering_init, model)
        self.agent = build_routed_agent("", router=self.router, agent_role='ranking_agent', system_prompt="") if router else build_agent("", model)
        
        self.task_tree = ''
        self.function_call_info_summary = {}
        self.current_task = ''
        self.processing_result = ''
        self.understanding_result = ''
        self.potentially_vulnerable_functions = {}
        self.children_call_memo_single = {}
        self.children_call_memo = {}
        self.repeated_patterns = []

    def _stage(self, name):
        """Time a pipeline stage when a CostTracker is attached, else no-op."""
        if self.cost_tracker is None:
            return nullcontext()
        return self.cost_tracker.stage(name)

    @staticmethod
    def _tier2_confidence(response, format='json') -> float:
        """Operational local-confidence signal for θ_gate escalation (audit-fixes).

        Local models report no numeric confidence, so confidence is measured
        as response validity: 1.0 for a well-formed response, 0.0 otherwise.
        """
        if format == 'str':
            return 1.0 if isinstance(response, str) and response.strip() else 0.0
        return 1.0 if isinstance(response, dict) and response else 0.0

    def _query_tier2(self, agent, prompt, format='json'):
        """Query a Tier-2 agent with θ_gate escalation (audit-fixes).

        Queries the local agent first; if the response is invalid, its
        confidence (0.0) falls below the router's ``confidence_gate`` and the
        agent is rebuilt on the cloud model for a single retry. Without a
        router attached this is a plain query.
        """
        response = agent.query(prompt, format=format)
        router = getattr(agent, 'router', None) or self.router
        if router is not None and router.should_escalate(
                getattr(agent, 'agent_role', ''),
                local_confidence=self._tier2_confidence(response, format)):
            try:
                escalated = router.escalate_agent(agent)
                logging.info("Tier-2 θ_gate escalation: retrying '%s' on cloud model",
                             getattr(agent, 'agent_role', 'tier2'))
                response = escalated.query(prompt, format=format)
            except Exception as e:
                logging.warning("Tier-2 escalation failed (%s); keeping local response", e)
        return response

    def _get_function_call_depth(self, function_call):
        temp = function_call.rsplit('_',1)
        function_name = temp[0].lower()
        address = temp[1].lower()
        key = f"{function_name}::{address}"
        current_depth = 0
        if key in self.tx_analysis['function_call_loc_memo']:
            for call in self.tx_analysis['function_call_loc_memo'][key]:
                if len(call['depth']) > current_depth:
                    current_depth = len(call['depth'])
        return current_depth
        
    def _retrieve_function_call_by_depth(self, depth , function_name, get_children=False):
        depth_temp = depth[:-1]
        current = deepcopy(self.trace)
        for d in depth_temp:
            current = current[d]['children']
        if get_children:
            output = []
            for c in current[depth[-1]]['children']:
                if c['function']:
                    if (c['function'] == function_name) and (c['call_type'] == 'delegatecall'):
                        output.extend(deepcopy(c['children']))
                    elif c['type'] not in ['return']:
                        output.append(deepcopy(c))      
            for c in output:                    
                c['children'] = [f"[{child['call_type']}]{child['address']}::{child['function']}({child['params']})" for child in c['children'] if child['function']]
            return output
        if depth[-1] < len(current):
            output = deepcopy(current[depth[-1]])
            output['children'] = [f"[{child['call_type']}]{child['address']}::{child['function']}({child['params']})" for child in output['children'] if child['function']]
            return output
        
    def _retrieve_chidlren_calls_memo_single(self, function, address):
        if f'{function}_{address}' in self.children_call_memo:
            self.children_call_memo_single = self.children_call_memo[f'{function}_{address}']
    
    def select_high_appearance_count_children_calls(self):
        function_info = {}
        # Filter out read-only functions and standard safe state-changing functions
        filtered_list = [
            # ERC20 read-only functions
            'totalSupply', 'balanceOf', 'allowance', 'decimals', 'name', 'symbol',
            # ERC721 read-only functions
            'ownerOf', 'balanceOf', 'tokenURI', 'getApproved', 'isApprovedForAll',
            # Uniswap/DEX read-only functions
            'token0', 'token1', 'getReserves', 'getAmountOut', 'getAmountIn',
            'getAmountsOut', 'getAmountsIn', 'factory', 'pair', 'getPair',
            # Other common read-only functions
            'paused', 'owner', 'admin', 'isPaused', 'totalShares', 'pricePerShare',
            # Standard state-changing functions (usually safe)
            'transfer', 'transferFrom', 'approve'
        ]
        filtered_list = [func.lower() for func in filtered_list]
        selected_functions = {}
        functions_to_be_included = {}
        for k,v in self.children_call_memo_single.items():
            function_name = k.split('::')[0]
            v_param_lower = str(v['params']).lower()
            for vi in self.txn_seq['created_address']:
                if vi.lower() in v_param_lower:
                    v['note'] = f"created address {vi} in params (this could suggest a risky action for insufficient validation if related to token transfers)"
                    function_info[k] = {'count': v['count'],'note': v['note']}
                    break
            if function_name.lower() not in filtered_list:
                selected_functions[k] = v
                if function_name.lower().startswith('set'):
                    functions_to_be_included[function_name] = v
        self.children_call_memo_single = selected_functions
        for k,v in sorted(self.children_call_memo_single.items(), key=lambda x: x[1]['count'], reverse=True)[:33]:
            if k not in function_info:
                function_info[k] = v['count']
        for k,v in sorted(functions_to_be_included.items(), key=lambda x: x[1]['count'], reverse=True)[:3]:
            if k not in function_info:
                function_info[k] = v['count']
        return function_info
    
    def _retrieve_function_calls(self, function_call):
        function_calls = []
        if isinstance(function_call, dict):
            function_name = function_call['function']
            address = function_call['address']
        else:
            function_name = function_call[1]
            address = function_call[0]
        if ('function' in self.function_call_info_summary) and (function_name == self.function_call_info_summary['function']):
            if 'calls' not in self.current_task:
                param_memo = []
                for call in self.function_call_info_summary['calls']:
                    if call['params'] not in param_memo:
                        param_memo.append(call['params'])
                        call_copy = deepcopy(call)
                        call_copy['function'] = function_name
                        function_calls.append(call_copy)
        else:
            key = f"{function_name}::{address}".lower()
            memo = []
            if key in self.tx_analysis['function_call_loc_memo']:
                for call in self.tx_analysis['function_call_loc_memo'][key]:
                    if call['params'] not in memo:
                        memo.append(call['params'])
                        function_calls.append(self._retrieve_function_call_by_depth(call['depth'],function_name=function_name))
        return function_calls
    
    def _retrieve_children_calls(self, function_name, address):
        calls = []
        function_calls = []
        if ('function' in self.function_call_info_summary) and (function_name == self.function_call_info_summary['function']):
            calls = self.function_call_info_summary['calls']
        else:
            key = f"{function_name}::{address}".lower()
            if key in self.tx_analysis['function_call_loc_memo']:
                calls = self.tx_analysis['function_call_loc_memo'][key]
        if calls:
                memo = []
                for call in calls:
                    if call['params'] not in memo:
                        memo.append(call['params'])
                        function_calls.extend(self._retrieve_function_call_by_depth(call['depth'],function_name=function_name,get_children=True))
        return function_calls

    def _retrieve_additional_info(self, additional_info):
        prompt = self.function_prompts.retrieve_additional_info
        prompt += f"Current available information:{self.function_call_info_summary}\n"
        prompt += f"Additional information to be reorganized:{additional_info}"
        formatted_additional_info = self._query_tier2(self.generation_agent, prompt)
        output = {}
        if 'function_call' in formatted_additional_info:
            function_call = []
            for f in formatted_additional_info['function_call']:
                function_call.extend(self._retrieve_function_calls(f))
            if function_call:
                output['function_call'] = function_call
        if 'children_calls' in formatted_additional_info:
            children_call = {}
            for function_call in formatted_additional_info['children_calls']:
                if isinstance(function_call, dict):
                    function_name = function_call['function']
                    address = function_call['address']
                else:
                    function_name = function_call[0]
                    address = function_call[1]
                children_call[f'{function_name}::{address}'] = self._retrieve_children_calls(function_name, address)
            if children_call:
                output['children_calls (i.e., for {k:v}, v is the children calls of k)'] = children_call
        if 'source_code' in formatted_additional_info:
            source_code = {}
            if isinstance(formatted_additional_info['source_code'], dict):
                function_name = formatted_additional_info['source_code']['function_name']
                address = formatted_additional_info['source_code']['address']
                if f'{function_name}::{address}' in self.function_call_info_summary['high_appearance_count_children_calls']:
                    key_list = list(self.function_call_info_summary['high_appearance_count_children_calls'].keys())
                    index = key_list.index(f'{function_name}::{address}')
                    if index + 1 < len(key_list):
                        next_key = key_list[index + 1]
                        next_function_name = next_key.split('::')[0]
                        next_address = next_key.split('::')[1]
                        if next_function_name == function_name:
                            address = next_address
                retrieved_source_code = self._retrieve_source_code(address, function_name)
                source_code[f'{function_name}_{address}'] = retrieved_source_code if retrieved_source_code else 'no source code found, proceed to other analysis for other functions'
            else:
                for temp in formatted_additional_info['source_code']:
                    if isinstance(temp, dict):
                        function_name = temp['function']
                        address = temp['address']
                    else:
                        function_name = temp[1]
                        address = temp[0]
                    if f'{function_name}::{address}' in self.function_call_info_summary['high_appearance_count_children_calls']:
                        key_list = list(self.function_call_info_summary['high_appearance_count_children_calls'].keys())
                        index = key_list.index(f'{function_name}::{address}')
                        if index + 1 < len(key_list):
                            next_key = key_list[index + 1]
                            next_function_name = next_key.split('::')[0]
                            next_address = next_key.split('::')[1]
                            if next_function_name == function_name:
                                address = next_address
                    retrieved_source_code = self._retrieve_source_code(address, function_name)
                    source_code[f'{function_name}_{address}'] = retrieved_source_code if retrieved_source_code else 'no source code found, proceed to other analysis'
            if source_code:
                output['source_code'] = source_code
        if 'balance_change' in formatted_additional_info:
            balance_change = {}
            for address in formatted_additional_info['balance_change']:
                address = address.lower()
                if address in self.fundflow_analysis['balance_change']:
                    balance_change[address] = deepcopy(self.fundflow_analysis['balance_change'][address])
                for addr in self.fundflow_analysis['balance_change']:
                    if addr != address:
                        if address in self.fundflow_analysis['balance_change'][addr]:
                            balance_change[addr] = deepcopy(self.fundflow_analysis['balance_change'][addr])
            if balance_change:
                output['balance_change'] = balance_change
        return output

    def _perform_task(self):
        if 'description' in self.current_task:
            self.current_task['task_description'] = self.current_task['description']
        if 'additional_information' not in self.current_task:
            self.current_task['additional_information'] = ''
        self.current_task['additional_information'] = self._retrieve_additional_info(str(self.current_task['additional_information'])+ self.current_task['task_description'])
        processing_prompt = self.function_prompts.function_call_info_processing.format(
            selected_task = json.dumps(self.current_task)
        )
        self.processing_result = self.processing_agent.query(processing_prompt, format='str')
        logging.info(f"Processing result: {self.processing_result}")

    def _select_task(self):
        task_selection_prompt = self.function_prompts.function_call_task_selection.format(
            task_tree = self.task_tree,
            function_call_info_summary = self.function_call_info_summary,
            current_understanding = self.understanding_result
        )
        self.current_task = self._query_tier2(self.generation_agent, task_selection_prompt)
        count = 0
        while (not isinstance(self.current_task, dict)) and (count < 3):
            self.current_task = self._query_tier2(self.generation_agent, 'The task is not in standard JSON format. Please reformat the task into a standard JSON format.')
            count += 1
        logging.info(f"Selected task: {self.current_task}")
        return self.current_task   # ← callers use this to detect timeouts (empty = timed out)

            
    def _update_task_tree(self):
        prompt = self.task_prompts.update_task_tree.format(
            task_tree = self.task_tree,
            current_understanding = self.understanding_result,
            task_completed = self.processing_result
        )
        result = self.reasoning_agent.query(prompt, format='str')
        self.task_tree = result
        logging.info(f"Task tree: {self.task_tree}")

    def _update_current_understanding(self, is_init=False):
        if is_init:
            understanding_prompt = self.function_prompts.function_call_organization_function_call.format(function_call_info_summary=json.dumps(self.function_call_info_summary))
            self.understanding_result = self._query_tier2(self.organization_agent, understanding_prompt, format='str')
        else:
            understanding_prompt = self.function_prompts.function_call_organization_function_call.format(function_call_info_summary=json.dumps(self.function_call_info_summary))
            self.understanding_result = self._query_tier2(self.organization_agent, understanding_prompt, format='str')
        logging.info(f"Current understanding: {self.understanding_result}")

    def _update_potentially_vulnerable_function(self):
        prompt = self.vulnerability_prompts.update_potentially_vulnerable_function
        prompt += "Current understanding:" + self.understanding_result
        prompt += "Current task:" + json.dumps(self.current_task)
        prompt += 'Analysis result of current task:' + json.dumps(self.processing_result)
        prompt += 'The following function calls have been confirmed to be vulnerable, if it is in the provided information, please add it to the returned JSON with the predefined format: ' + str(self.cheatsheet)
        result = self._query_tier2(self.organization_agent, prompt)
        logging.info(f"Vulnerable function: {result}")
        for key in result:
            try:
                evidence = ''
                confidence_score = ''
                if isinstance(result[key],list) or isinstance(result[key],tuple):
                    evidence = result[key][0]
                    confidence_score = result[key][1]
                elif isinstance(result[key],dict):
                    evidence = result[key]['evidence']
                    confidence_score = result[key]['confidence_score']
                if evidence and confidence_score:
                    if key not in self.potentially_vulnerable_functions:
                        self.potentially_vulnerable_functions[key] = {
                            'confidence_score': [confidence_score],
                            'evidence': [evidence],
                            'depth': self._get_function_call_depth(key),
                        }
                    else:
                        self.potentially_vulnerable_functions[key]['confidence_score'].append(confidence_score)
                        self.potentially_vulnerable_functions[key]['evidence'].append(evidence)
            except Exception:
                pass
    
    def _update_children_call_memo(self, function_call, function_name=''):
        for i in function_call:
            if (i['function'] == function_name) and (i['call_type'] == 'delegatecall'):
                self._update_children_call_memo(i['children'])
            elif i['type'] not in ['return']:
                ii = deepcopy(i)
                del ii['children']
                key = f"{i['function']}::{i['address']}"
                if key not in self.children_call_memo_single:
                    self.children_call_memo_single[key] = {
                        'count': 1,
                        'call_details':ii,
                        'params': [i['params']],
                    }
                else:
                    self.children_call_memo_single[key]['count'] += 1
                    if i['params'] not in self.children_call_memo_single[key]['params']:
                        self.children_call_memo_single[key]['params'].append(i['params'])
                self._update_children_call_memo(i['children'])

    def _prepare_children_call_memo(self, function_calls):
        for function in function_calls:
            if function not in self.functions_to_be_inspected:
                keys = list(self.functions_to_be_inspected.keys())
                lower_keys = [i.lower() for i in keys]
                if function.lower() not in lower_keys:
                    continue
                function = keys[lower_keys.index(function.lower())]
            for function_call in self.functions_to_be_inspected[function]['calls']:
                current_output = deepcopy(self.trace)
                for d in function_call['depth']:
                    current_output = current_output[d]['children']
                    self._update_children_call_memo(current_output, function.split('_')[0])
            self.children_call_memo[function] = self.children_call_memo_single
            self.children_call_memo_single = {}
    
    def _temp_check(self):
        return False
    
    def _function_analysis_init(self):
        if self._temp_check():
            return
        self._update_current_understanding(is_init=True)
        prompt = self.function_prompts.function_analysis_init_prompt
        initial_task_tree = '''1. Basic Function Call Info Gathering - [completed]
   1.1 Summary of appearance in the transaction - (completed)
   1.2 Summary of the relation with other addresses - (completed)
   1.3 Retrieve the source code of the function call - (completed)
'''
        prompt = prompt.format(
            task_tree = initial_task_tree,
            current_understanding = self.understanding_result,
            function_call_info_summary = json.dumps(self.function_call_info_summary)
        )
        result = self.reasoning_agent.query(prompt, format='str')
        self.task_tree = result
        logging.info(f"Function call info summary: {json.dumps(self.function_call_info_summary)}")
        logging.info(f"Current understanding: {self.understanding_result}")
        logging.info(f"Task tree: {self.task_tree}")

        # Cloud models need fewer iterations than local; 3 passes is plenty.
        is_cloud = any(self.txn_analyzer_model.startswith(p)
                       for p in ('gpt-', 'gemini-', 'grok-', 'qwen-', 'claude-', 'o1-', 'o3-', 'o4-'))
        max_iterations = 3 if is_cloud else 8
        MAX_FUNCTION_SECS = 480   # 8-min hard wall-clock cap per function

        import time as _time
        fn_start = _time.time()
        i = 0
        consecutive_timeouts = 0
        while True:
            i += 1
            elapsed = int(_time.time() - fn_start)
            print(f"         [Info] Iteration {i}/{max_iterations}  ({elapsed}s elapsed)", flush=True)
            if _time.time() - fn_start > MAX_FUNCTION_SECS:
                print(f"   [Time] Function analysis exceeded {MAX_FUNCTION_SECS}s wall-clock limit -- moving on.")
                break
            task = self._select_task()
            if not task or not str(task).strip():
                consecutive_timeouts += 1
                if consecutive_timeouts >= 2:
                    print("   [!] Model timed out repeatedly -- skipping this function.")
                    break
                continue
            consecutive_timeouts = 0
            try:
                self._perform_task()
                self._update_current_understanding()
                self._update_task_tree()
                self._update_potentially_vulnerable_function()
                if self._temp_check():
                    break
                if i % 2 == 0:
                    check_prompt = self.function_prompts.check_analysis_adequacy
                    check_prompt += "Current understanding:" + self.understanding_result
                    result = self._query_tier2(self.organization_agent, check_prompt, format='str')
                    if result and 'yes' in str(result).lower():
                        break
            except Exception:
                if self.potentially_vulnerable_functions:
                    break
            if i >= max_iterations:
                break
        
    def _retrieve_source_code(self, address, function_name):
        output = []
        output_memo = []
        address = address.lower()
        contract_info = self.contract_info
        if address not in self.contract_info:
            contract_info = ContractDownloader(self.analysis_result.chain,[address]).run()
        if address in contract_info:
            if function_name in contract_info[address]:
                source_code_list = contract_info[address][function_name]
                for source_code in source_code_list:
                    if source_code['start_line'] != source_code['end_line']:
                        if source_code['content'] not in output_memo:
                            output_memo.append(source_code['content'])
                            output.append({'path':source_code['path'],'source_code':source_code['content']})
        return output

    def _retrieve_related_info(self, address, function_name):
        output = {}
        related_balance_change = {}
        address = address.lower()
        if address in self.fundflow_analysis['balance_change']:
            related_balance_change = deepcopy(self.fundflow_analysis['balance_change'][address])
        for key,value in self.fundflow_analysis['balance_change'].items():
            if (key!=address) and (address in value):
                related_balance_change[key] = deepcopy(value)
        if related_balance_change:
            output['related_balance_change'] = related_balance_change
        address_calls = []
        if address in self.txn_seq['address_calls']:
            address_calls = self.txn_seq['address_calls'][address]
        if address_calls:
            output['address_calls'] = address_calls
        relations_with_other_addresses = []
        if address in self.address_relation.nodes():
            relations_with_other_addresses.extend(list(self.address_relation.out_edges(address, data=True)))
            relations_with_other_addresses.extend(list(self.address_relation.in_edges(address, data=True)))
        if relations_with_other_addresses:
            output['relations_with_other_addresses(i.e., sender, receiver, function)'] = relations_with_other_addresses
        function_source_code = self._retrieve_source_code(address, function_name)
        if function_source_code:
            output['function_source_code'] = function_source_code
        return output
    
    def _finalize_potentially_vulnerable_functions(self):
        current_depth = 0
        finalized_potentially_vulnerable_functions = []
        for key in self.potentially_vulnerable_functions:
            if self.potentially_vulnerable_functions[key]['depth'] > current_depth:
                current_depth = self.potentially_vulnerable_functions[key]['depth']
                potentially_vulnerable_functions = deepcopy(self.potentially_vulnerable_functions[key])
                temp = key.rsplit('_',1)
                function_name = temp[0]
                address = temp[1].lower()
                potentially_vulnerable_functions['function'] = function_name
                potentially_vulnerable_functions['address'] = address
                finalized_potentially_vulnerable_functions = [potentially_vulnerable_functions]
            elif self.potentially_vulnerable_functions[key]['depth'] == current_depth:
                potentially_vulnerable_functions = deepcopy(self.potentially_vulnerable_functions[key])
                temp = key.rsplit('_',1)
                function_name = temp[0]
                address = temp[1].lower()
                potentially_vulnerable_functions['function'] = function_name
                potentially_vulnerable_functions['address'] = address
                finalized_potentially_vulnerable_functions.append(potentially_vulnerable_functions)
        return finalized_potentially_vulnerable_functions
        
    def _process_potentially_vulnerable_functions(self):
        potentially_vulnerable_functions = {}
        for func in self.potentially_vulnerable_functions:
            potentially_vulnerable_functions[func] = {
                'evidence': self.potentially_vulnerable_functions[func]['evidence'],
                'confidence_score': self.potentially_vulnerable_functions[func].get('confidence_score', []),
                'depth': self.potentially_vulnerable_functions[func].get('depth', 0),
            }
        self.potentially_vulnerable_functions = potentially_vulnerable_functions

    def _rank_potentially_vulnerable_functions(self):
        prompt_text = self.vulnerability_prompts.rank_potentially_vulnerable_functions.format(
            current_understanding=json.dumps(self.understanding_result),
            potentially_vulnerable_functions=json.dumps(self.potentially_vulnerable_functions)
        )
        self.ranked_result = self._query_tier2(self.agent, prompt_text)

    def _review_function_calls(self):
        self.examined_function_memo = []
        selected_functions = {k:v['count'] for k,v in self.functions_to_be_inspected.items()}
        count = 0
        while (len(selected_functions) > 5) and (count < 3):
            count += 1
            function_call_to_be_inspected_summary = {}
            for function_call in self.functions_to_be_inspected:
                function_call_to_be_inspected_summary[function_call] = {
                    'count_of_appearance': self.functions_to_be_inspected[function_call]['count'],
                    'example_calls': self.functions_to_be_inspected[function_call]['calls'][:3]
                }
            prompt = self.function_prompts.narrow_down_functions.format(
                function_call_to_be_inspected = json.dumps(function_call_to_be_inspected_summary),
                balance_change = json.dumps(self.fundflow_analysis['balance_change'])
            )
            selected_functions_new = self._query_tier2(self.agent, prompt)
            if len(selected_functions_new) < len(selected_functions):
                selected_functions = selected_functions_new
        selected_functions_with_created_contract_in_params = list(self.address_calls_with_created_contract_in_params.keys())
        count = 0
        while (len(selected_functions_with_created_contract_in_params) > 5) and (count < 3):
            count += 1
            function_call_to_be_inspected_summary = {}
            for function_call in self.address_calls_with_created_contract_in_params:
                function_call_to_be_inspected_summary[function_call] = {
                    'count_of_appearance': self.address_calls_with_created_contract_in_params[function_call]['count'],
                    'example_calls': self.address_calls_with_created_contract_in_params[function_call]['calls'][:3]
                }
            prompt = self.function_prompts.narrow_down_functions_with_created_contracts.format(
                function_call_to_be_inspected = json.dumps(function_call_to_be_inspected_summary),
            )
            selected_functions_new = self._query_tier2(self.agent, prompt)
            if len(selected_functions_new) < len(selected_functions_with_created_contract_in_params):
                selected_functions_with_created_contract_in_params = selected_functions_new
        
        self._prepare_children_call_memo(selected_functions)

        total_functions = len(self.repeated_patterns) + len(selected_functions_with_created_contract_in_params) + len(selected_functions)
        current = 0
        print('repeated patterns to be analyzed:', self.repeated_patterns)
        for repeated_pattern in self.repeated_patterns:
            current += 1
            print(f"         [{current}/{total_functions}] Analyzing repeated pattern...")
            self.task_tree = ''
            self.function_call_info_summary = {}
            self.current_task = ''
            self.processing_result = ''
            self.children_call_memo_single = {}
            if 'start_index' in repeated_pattern:
                del repeated_pattern['start_index']
            if 'end_index' in repeated_pattern:
                del repeated_pattern['end_index']
            self.function_call_info_summary = repeated_pattern
            function_call_related_info = {}
            for f in repeated_pattern['pattern']:
                if f['function']:
                    self.examined_function_memo.append(f['function'])
                    related_info = self._retrieve_related_info(f['address'], f['function'])
                    if related_info:
                        current_output = deepcopy(self.trace)
                        for d in f['depth']:
                            current_output = current_output[d]['children']
                        self._update_children_call_memo(current_output, f['function'])
                        function_call_related_info[f"{f['function']}::{f['address']}"] = related_info
            self.function_call_info_summary['function_call_related_info'] = function_call_related_info
            self.function_call_info_summary['high_appearance_count_children_calls'] = self.select_high_appearance_count_children_calls()
            self._function_analysis_init()
            repeated_pattern['analysis_result'] = {
                'task_tree': self.task_tree,
                'function_call_info_summary': self.function_call_info_summary,
                'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
                'current_understanding': self.understanding_result
            }
        print('functions with created contract in params to be analyzed:', selected_functions_with_created_contract_in_params)
        for function in selected_functions_with_created_contract_in_params:
            function = function.split('_')[0]
            if function in self.examined_function_memo:
                continue
            self.examined_function_memo.append(function)
            if function in self.address_calls_with_created_contract_in_params:
                current += 1
                print(f"         [{current}/{total_functions}] Analyzing {function} (created contract param)...")
                self.task_tree = ''
                self.function_call_info_summary = {}
                self.current_task = ''
                self.processing_result = ''
                # self.understanding_result = ''
                self.children_call_memo_single = {}
                function_name = function
                appearance_count = self.address_calls_with_created_contract_in_params[function]['count']
                function_calls = self.address_calls_with_created_contract_in_params[function]['calls']
                # self._retrieve_children_calls(function_calls,function_name)
                self.function_call_info_summary = {
                    'function': function_name,
                    'appearance_count': appearance_count,
                    'calls': function_calls,
                    'note': 'this function contains a created contract in its params'
                }
                address_related_info = {}
                self.children_call_memo_single = {}
                for address in self.address_calls_with_created_contract_in_params[function]['address']:
                    related_info = self._retrieve_related_info(address, function_name)
                    if related_info:
                        current_output = deepcopy(self.trace)
                        for d in function_calls[0]['depth']:
                            current_output = current_output[d]['children']
                        self._update_children_call_memo(current_output, function_name)
                        address_related_info[address] = related_info
                if address_related_info:
                    self.function_call_info_summary['address_related_info'] = address_related_info
                self.function_call_info_summary['high_appearance_count_children_calls'] = self.select_high_appearance_count_children_calls()
                self._function_analysis_init()
                self.address_calls_with_created_contract_in_params[function]['analysis_result'] = {
                    'task_tree': self.task_tree,
                    'function_call_info_summary': self.function_call_info_summary,
                    'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
                    'current_understanding': self.understanding_result
                }
        print('functions to be analyzed:', selected_functions)
        for function in selected_functions:
            if function in self.functions_to_be_inspected:
                self.task_tree = ''
                self.function_call_info_summary = {}
                self.current_task = ''
                self.processing_result = ''
                # self.understanding_result = ''
                temp = function.split('_')
                function_name = temp[0]
                address = temp[1]
                if function_name in self.examined_function_memo:
                    continue
                self.examined_function_memo.append(function_name)
                current += 1
                print(f"         [{current}/{total_functions}] Analyzing {function_name}...")
                appearance_count = self.functions_to_be_inspected[function]['count']
                function_calls = self.functions_to_be_inspected[function]['calls']
                # self._retrieve_children_calls(function_calls,function_name)
                related_info = self._retrieve_related_info(address, function_name)
                self.function_call_info_summary = {
                    'function': function_name,
                    'address': address,
                    'appearance_count': appearance_count,
                    'calls': function_calls,
                }
                if related_info:
                    self.function_call_info_summary.update(related_info)
                self._retrieve_chidlren_calls_memo_single(function_name,address)
                self.function_call_info_summary['high_appearance_count_children_calls'] = self.select_high_appearance_count_children_calls()
                self._function_analysis_init()
                self.functions_to_be_inspected[function]['analysis_result'] = {
                    'task_tree': self.task_tree,
                    'function_call_info_summary': self.function_call_info_summary,
                    'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
                    'current_understanding': self.understanding_result
                }
                
    def _txn_analysis_init(self):
        self._update_current_understanding(is_init=True)
        prompt = self.function_prompts.function_analysis_init_prompt
        initial_task_tree = '''1. Basic Function Call Info Gathering - [completed]
   1.1 Summary of appearance in the transaction - (completed)
   1.2 Summary of the relation with other addresses - (completed)
   1.3 Retrieve the source code of the function call - (completed)
'''
        prompt = prompt.format(
            task_tree = initial_task_tree,
            current_understanding = self.understanding_result,
            function_call_info_summary = json.dumps(self.function_call_info_summary)
        )
        result = self.reasoning_agent.query(prompt, format='str')
        self.task_tree = result

        logging.info(f"Function call info summary: {json.dumps(self.function_call_info_summary)}")
        logging.info(f"Current understanding: {self.understanding_result}")
        logging.info(f"Task tree: {self.task_tree}")

        import time as _time
        is_cloud = any(self.txn_analyzer_model.startswith(p)
                       for p in ('gpt-', 'gemini-', 'grok-', 'qwen-', 'claude-', 'o1-', 'o3-', 'o4-'))
        txn_iters = 2 if is_cloud else 3
        fn_start = _time.time()
        MAX_FUNCTION_SECS = 480

        consecutive_timeouts = 0
        for i in range(txn_iters):
            elapsed = int(_time.time() - fn_start)
            print(f"         [Info] Sub-iteration {i+1}/{txn_iters}  ({elapsed}s elapsed)", flush=True)
            if _time.time() - fn_start > MAX_FUNCTION_SECS:
                print(f"   [Time] Sub-analysis exceeded wall-clock limit -- moving on.")
                break
            task = self._select_task()
            if not task or not str(task).strip():
                consecutive_timeouts += 1
                if consecutive_timeouts >= 2:
                    print("   [!] Model timed out repeatedly -- skipping this function.")
                    break
                continue
            consecutive_timeouts = 0
            try:
                self._perform_task()
                self._update_current_understanding()
                self._update_task_tree()
                self._update_potentially_vulnerable_function()
                if i > 0:
                    check_prompt = self.function_prompts.check_analysis_adequacy_alt
                    check_prompt += "Current understanding:" + self.understanding_result
                    result = self._query_tier2(self.organization_agent, check_prompt, format='str')
                    if result and 'yes' in str(result).lower():
                        break
            except Exception:
                if self.potentially_vulnerable_functions:
                    break
    
    def run(self, forensics_result, txn_seq: dict, txn_info: dict, ranking_result: RankingResult) -> dict:
        """
        Run function analysis using forensics results from Stage 1 and ranking results.

        Args:
            forensics_result: ForensicsResult object from Stage 1
            txn_seq: Transaction sequence data
            txn_info: Transaction info data
            ranking_result: RankingResult from FunctionRanker

        Returns:
            Dictionary containing function analysis results
        """
        # Initialize state
        self.task_tree = ''
        self.txn_hash = forensics_result.transaction_hash
        self.cheatsheet = []

        # Store Stage 1 outputs
        self.analysis_result = forensics_result
        self.txn_seq = txn_seq
        self.txn_info = txn_info

        # ── Inject pre-computed signals as LLM context ──────────────────
        self.rule_verdict    = getattr(forensics_result, 'rule_verdict', 'UNKNOWN')
        self.rule_confidence = getattr(forensics_result, 'rule_confidence', 0.0)
        self.vuln_type_hint  = getattr(forensics_result, 'vuln_type_hint', '')
        self.signals_raw     = getattr(forensics_result, 'signals', {})
        # Seed the cheatsheet so the LLM prompt includes confirmed signals
        if self.rule_verdict == 'EXPLOIT' and self.vuln_type_hint:
            self.cheatsheet.append({
                'type': self.vuln_type_hint,
                'confidence': self.rule_confidence,
                'source': 'rule_classifier',
                'signals': self.signals_raw,
            })

        # Store ranking results
        self.repeated_patterns = ranking_result.repeated_patterns
        self.address_calls_with_created_contract_in_params = ranking_result.address_calls_with_created_contract_in_params
        self.functions_to_be_inspected = ranking_result.functions_to_be_inspected
        self.address_list = ranking_result.address_list

        if not (self.txn_seq and self.txn_info and self.analysis_result):
            return None

        if not self.txn_info.get('transaction_hash'):
            return None

        start_time = time.time()

        # Prepare trace data from forensics result
        self.tx_analysis = {
            'transaction_hash': forensics_result.transaction_hash,
            'chain': forensics_result.chain,
            'trace': forensics_result.trace,
            'address_relation': self.txn_seq['address_relation'],
            'address_calls': self.txn_seq['address_calls'],
            'created_address': self.txn_seq['created_address'],
            'repeated_patterns': forensics_result.repeated_patterns,
            'function_calls_to_expand_loc': forensics_result.function_calls_to_expand_loc,
            'address_calls_with_created_contract_in_params': forensics_result.address_calls_with_created_contract,
            'flatten_trace': forensics_result.flatten_trace,
            'function_call_loc_memo': forensics_result.function_call_loc_memo
        }

        # Prepare fund flow analysis from forensics result
        self.fundflow_analysis = {
            'balance_change': forensics_result.balance_change,
            'address_memo': forensics_result.address_memo,
            'potential_attacker': forensics_result.potential_attacker,
            'potential_victim': forensics_result.potential_victim
        }

        self.trace = [forensics_result.trace]
        self.address_relation = nx.node_link_graph(self.txn_seq['address_relation'], directed=True, edges='edges')

        print("      [+] Downloading contract source code...")
        self.contract_info = ContractDownloader(self.analysis_result.chain, self.address_list).run()

        with self._stage('stage2_llm_analysis'):
            print("      [+] Reviewing function calls...")
            self._review_function_calls()

            self._process_potentially_vulnerable_functions()
            self._rank_potentially_vulnerable_functions()

        # Finalize vulnerable functions with confidence scores preserved
        finalized_functions = self._finalize_potentially_vulnerable_functions()
        priority = compute_priority_breakdown(
            self.signals_raw,
            exploitability_score=self.rule_confidence,
        )

        # Build result — include signal layer outputs for downstream / eval
        result = {
            'duration': time.time() - start_time,
            'ranked_result': self.ranked_result,
            'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
            'finalized_vulnerable_functions': finalized_functions,
            'transaction_understanding': self.understanding_result,
            'functions_to_be_inspected': self.functions_to_be_inspected,
            # ── Signal layer (from Stage 1) ───────────────────────────────
            'reentrancy':     extract_reentrancy_analysis(self.signals_raw),
            'priority':       priority,
            'priority_score': priority['total'],
            'rule_verdict':    self.rule_verdict,
            'rule_confidence': self.rule_confidence,
            'vuln_type_hint':  self.vuln_type_hint,
            'signals':         self.signals_raw,
        }

        return result
