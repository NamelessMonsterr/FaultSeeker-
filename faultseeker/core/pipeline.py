import os
import json
import time
import re
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
from faultseeker.core.config import FaultSeekerConfig
from faultseeker.core.confidence_scorer import ConfidenceScorer, generate_evidence_card
from faultseeker.core.human_interface import HumanInterface
from faultseeker.core.llm_router import HybridLLMRouter
from faultseeker.forensics.result import (
    extract_reentrancy_analysis,
    compute_priority_breakdown,
)
from faultseeker.research.calibration import LogisticConfidenceCalibrator


class FaultSeekerPipeline:

    def __init__(self, config: FaultSeekerConfig):
        """
        Initialize the FaultSeeker pipeline.

        Args:
            config: FaultSeeker configuration object
        """
        self.config = config
        self.forensics_orchestrator = None
        self.function_analyzer = None
        self.router = None
        self._agents_initialized = False

    @staticmethod
    def _parse_txn_link(txn_link: str) -> Tuple[str, str]:
        # Extract transaction hash (0x followed by 64 hex characters)
        pattern = r'(0x[0-9a-fA-F]{64})'
        matches = re.findall(pattern, txn_link)
        if not matches:
            raise ValueError(f"Could not extract transaction hash from link: {txn_link}")
        txn_hash = matches[0]

        # Determine chain from URL (Gap 5: Multi-Chain — expanded from 2 to 8 chains)
        txn_link_lower = txn_link.lower()
        chain_map = [
            ('bscscan', 'bsc'),
            ('bsc', 'bsc'),
            ('polygonscan', 'polygon'),
            ('polygon', 'polygon'),
            ('arbiscan', 'arbitrum'),
            ('arbitrum', 'arbitrum'),
            ('optimistic.etherscan', 'optimism'),
            ('optimism', 'optimism'),
            ('snowtrace', 'avalanche'),
            ('avalanche', 'avalanche'),
            ('basescan', 'base'),
            ('base', 'base'),
            ('ftmscan', 'fantom'),
            ('fantom', 'fantom'),
            # Gap 3 fix: add zksync and gnosis (benchmark chains 9 & 10)
            ('explorer.zksync', 'zksync'),
            ('zksync', 'zksync'),
            ('gnosisscan', 'gnosis'),
            ('gnosis', 'gnosis'),
            ('etherscan', 'eth'),
            ('eth', 'eth'),
        ]
        chain = None
        for keyword, chain_id in chain_map:
            if keyword in txn_link_lower:
                chain = chain_id
                break
        if not chain:
            raise ValueError(f"The blockchain network is not supported: {txn_link}")

        return txn_hash, chain

    def _initialize_agents(self):
        if self._agents_initialized:
            return

        # Gap 1+6: Build router if auto_route is enabled
        if getattr(self.config, 'auto_route', False):
            # Use the dedicated cloud_model if set; fall back to function_analysis_model
            router_cloud = (getattr(self.config, 'cloud_model', '') or
                            self.config.function_analysis_model or
                            self.config.forensics_model)
            self.router = HybridLLMRouter(
                local_model=getattr(self.config, 'local_model', 'llama3:8b'),
                cloud_model=router_cloud,
                confidence_gate=getattr(self.config, 'confidence_gate', 0.6),
                track_cost=getattr(self.config, 'track_cost', False),
                routing_strategy=getattr(self.config, 'routing_strategy', 'hybrid'),
            )

        print("   [+] Initializing forensics orchestrator...")
        from faultseeker.forensics.orchestrator import ForensicsOrchestrator
        from faultseeker.function_analysis.function_ranker import FunctionRanker
        from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer

        # Initialize Stage 1: Forensics (pass router for intelligent routing)
        self.forensics_orchestrator = ForensicsOrchestrator(
            model=self.config.forensics_model,
            cache_dir=self.config.get_forensics_cache_dir(),
            router=self.router,
        )

        print("   [+] Initializing function ranker...")
        self.function_ranker = FunctionRanker()

        print("   [+] Initializing function analyzer...")
        # Initialize Stage 2b: Function Analysis (pass router for intelligent routing)
        self.function_analyzer = FunctionAnalyzer(
            model=self.config.function_analysis_model,
            router=self.router,
        )

        self._agents_initialized = True

    def analyze_transaction(self,
                          txn_link: Optional[str] = None,
                          txn_hash: Optional[str] = None,
                          chain: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a transaction and identify vulnerabilities.

        Args:
            txn_link: Transaction link (e.g., https://etherscan.io/tx/0x...)
            txn_hash: Transaction hash (alternative to txn_link)
            chain: Blockchain identifier (required if txn_hash is provided)

        Returns:
            Dictionary containing forensics and function analysis results

        Raises:
            ValueError: If input parameters are invalid
            RuntimeError: If analysis stages fail
        """
        start_time = time.time()

        # Validate and parse input
        if not txn_link and not (txn_hash and chain):
            raise ValueError("Either txn_link or (txn_hash and chain) must be provided")

        # Parse txn_link if provided
        if txn_link:
            txn_hash, chain = self._parse_txn_link(txn_link)

        # Ensure agents are initialized
        self._initialize_agents()

        print("\n[Stage 1] Transaction-Level Forensics")
        print("   [+] Fetching transaction data from blockchain...")

        # Stage 1: Transaction-Level Forensics
        forensics_result, txn_seq, txn_info = self.forensics_orchestrator.run(txn_hash, chain)

        if not forensics_result:
            raise RuntimeError("Stage 1 (Forensics) failed to produce results")

        print("   [OK] Forensics analysis completed")

        # Gap 8: Med-B - Trace Visualization (Visualizes trace tree and call types)
        try:
            import matplotlib.pyplot as plt
            viz_dir = getattr(self.config, 'output_dir', './data/output')
            os.makedirs(viz_dir, exist_ok=True)
            viz_path = os.path.join(viz_dir, f"{txn_hash}_trace.png")
            self.forensics_orchestrator.txn_sequencer.save_visualization(viz_path)
            plt.close('all')
            print(f"   [OK] Trace visualization saved to {viz_path}")
        except Exception as e:
            print(f"   [!] Note: Could not generate trace visualization: {str(e)}")

        # Gap 2: HITL Checkpoint 1 — Post-Forensics
        hitl = HumanInterface(enabled=getattr(self.config, 'human_in_loop', False))
        hitl_feedback_1 = hitl.checkpoint_post_forensics(forensics_result)
        if hitl_feedback_1.action == 'modify':
            print("   [Analyst] Analyst modifications recorded")

        print("\n[Stage 2] Task-Driven Function Analysis")
        print("   [+] Ranking suspicious functions...")

        # BENIGN fast-path (audit-fixes): the RuleClassifier found positive
        # evidence that no contract code executed, so no contract exploit is
        # possible — skip Stage 2 (ranking + LLM analysis) entirely.
        if getattr(forensics_result, 'rule_verdict', '') == 'BENIGN':
            print("   [OK] Rule verdict BENIGN (no contract execution) — skipping Stage 2")
            analysis_result = {
                'finalized_vulnerable_functions': [],
                'skipped_stage2': True,
                'skip_reason': 'BENIGN rule verdict: no contract code executed',
                'rule_verdict': 'BENIGN',
            }
        else:
            # Stage 2a: Function Ranking (fast, deterministic)
            tx_analysis = {
                'transaction_hash': forensics_result.transaction_hash,
                'chain': forensics_result.chain,
                'trace': forensics_result.trace,
                'repeated_patterns': forensics_result.repeated_patterns,
                'function_call_loc_memo': forensics_result.function_call_loc_memo
            }
            ranking_result = self.function_ranker.rank(forensics_result, tx_analysis)

            print(f"   [OK] Ranking completed - {len(ranking_result.address_list)} addresses to analyze")
            print("   [+] Analyzing vulnerable functions...")

            # Stage 2b: In-Depth Function Analysis (LLM-driven, uses ranking output)
            analysis_result = self.function_analyzer.run(forensics_result, txn_seq, txn_info, ranking_result)

            if not analysis_result:
                raise RuntimeError("Stage 2 (Function Analysis) failed to produce results")

            print("   [OK] Function analysis completed")

        # Stage 3: Confidence Scoring — paper §3.6 + §5.3
        # The 4-factor formula C(f) = 0.30·PMS + 0.25·CES + 0.25·TCS + 0.20·LCS
        # is computed first as a ranked proxy. When a pre-trained logistic calibrator
        # is available it *replaces* the proxy score as the final reported value,
        # matching the paper's reported FPR=0.003 result (§6.4 / Table 4).
        finalized_functions = analysis_result.get('finalized_vulnerable_functions', [])
        scored_functions = []
        evidence_cards = []
        if finalized_functions:
            print("\n[Stage 3] Confidence Scoring")
            scorer = ConfidenceScorer()
            forensics_data = {
                'repeated_patterns': forensics_result.repeated_patterns if hasattr(forensics_result, 'repeated_patterns') else [],
                'balance_change': forensics_result.balance_change if hasattr(forensics_result, 'balance_change') else {},
                'potential_attacker': forensics_result.potential_attacker if hasattr(forensics_result, 'potential_attacker') else [],
                'potential_victim': forensics_result.potential_victim if hasattr(forensics_result, 'potential_victim') else [],
            }
            scored_functions = scorer.score_all(finalized_functions, forensics_data)

            # Paper §5.3: replace proxy score with logistic calibrator when model present
            calibration_path = getattr(self.config, 'calibration_model_path', '')
            if not calibration_path:
                # Auto-discover default model location
                _default = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    'data', 'models', 'calibrator.json'
                )
                if os.path.exists(_default):
                    calibration_path = _default

            if calibration_path and os.path.exists(calibration_path):
                try:
                    calibrator = LogisticConfidenceCalibrator.load(calibration_path)
                    print(f"   [OK] Logistic calibrator loaded from {calibration_path}")
                    for sf in scored_functions:
                        # Build the 8-feature vector expected by the calibrator
                        conf = sf.get('confidence', {})
                        comps = conf.get('components', {}) if isinstance(conf, dict) else {}
                        stage1_signals = getattr(forensics_result, 'signals', {}) or {}
                        row = {
                            'pattern_match':      comps.get('pattern_match', 0.0),
                            'code_evidence':      comps.get('code_evidence', 0.0),
                            'txn_consistency':    comps.get('txn_consistency', 0.0),
                            'llm_confidence':     comps.get('llm_confidence', 0.0),
                            'trace_entropy':      float(stage1_signals.get('trace_entropy', 0.0) or 0.0),
                            'call_depth':         float(stage1_signals.get('call_depth', 0.0) or 0.0),
                            'state_delta':        float(stage1_signals.get('state_delta', 0.0) or 0.0),
                            'token_flow_anomaly': float(stage1_signals.get('token_flow_anomaly', 0.0) or 0.0),
                        }
                        calibrated_prob = calibrator.predict_proba(row)
                        # Update the confidence dict with calibrated score
                        if isinstance(sf.get('confidence'), dict):
                            sf['confidence']['overall'] = round(calibrated_prob, 4)
                            sf['confidence']['calibrated'] = True
                            sf['confidence']['calibration_model'] = calibration_path
                        else:
                            sf['confidence'] = {
                                'overall': round(calibrated_prob, 4),
                                'calibrated': True,
                                'calibration_model': calibration_path,
                            }
                    # Re-sort by calibrated score
                    scored_functions.sort(key=lambda x: x.get('confidence', {}).get('overall', 0.0), reverse=True)
                    print(f"   [OK] Calibrated {len(scored_functions)} functions (logistic calibrator, paper §5.3)")
                except Exception as _cal_err:
                    print(f"   [!] Calibrator load failed ({_cal_err}); using 4-factor heuristic")
            else:
                print(f"   [OK] Scored {len(scored_functions)} functions (4-factor heuristic; no calibrator model found)")

            for sf in scored_functions:
                card = generate_evidence_card(sf, sf.get('confidence', {}))
                evidence_cards.append(card)


        # Gap 2: HITL Checkpoint 2 — Vulnerability Review (after scoring)
        hitl_feedback_2 = hitl.checkpoint_vulnerability_review(scored_functions)
        if hitl_feedback_2.action == 'modify':
            # Apply analyst confirmations to evidence cards — match by function name
            confirmations = hitl_feedback_2.modifications.get('confirmations', {})
            analyst_notes_global = hitl_feedback_2.modifications.get('analyst_notes', '')
            for card in evidence_cards:
                func_name = card.get('function_signature', {}).get('function', '')
                if func_name in confirmations:
                    conf_entry = confirmations[func_name]
                    card['analyst_notes'] = conf_entry.get('note', '')
                    card['analyst_confirmed'] = conf_entry.get('confirmed', None)
                elif analyst_notes_global:
                    card['analyst_notes'] = analyst_notes_global

        # Build clean final output with only essential results
        reentrancy = extract_reentrancy_analysis(getattr(forensics_result, 'signals', {}))
        priority = compute_priority_breakdown(
            getattr(forensics_result, 'signals', {}),
            exploitability_score=getattr(forensics_result, 'rule_confidence', 0.0),
        )
        result = {
            'transaction_hash': forensics_result.transaction_hash,
            'chain': forensics_result.chain,

            # Stage 1.5 rule verdict (audit-fixes: BENIGN skips Stage 2)
            'rule_verdict': getattr(forensics_result, 'rule_verdict', 'UNKNOWN'),
            'rule_confidence': getattr(forensics_result, 'rule_confidence', 0.0),
            'skipped_stage2': bool(analysis_result.get('skipped_stage2', False)),
            'skip_reason': analysis_result.get('skip_reason', ''),

            # Main analysis results
            'ranked_suspicious_functions': analysis_result.get('ranked_result', []),
            'potentially_vulnerable_functions': analysis_result.get('potentially_vulnerable_functions', []),
            'transaction_understanding': analysis_result.get('transaction_understanding', ''),

            # Gap 3+4: Confidence scores and evidence cards
            'scored_functions': scored_functions,
            'evidence_cards': evidence_cards,
            'reentrancy': reentrancy,
            'priority': priority,
            'priority_score': priority['total'],

            # Gap 2: Analyst feedback log
            'analyst_feedback': hitl.get_feedback_log(),

            # Metadata
            'duration': time.time() - start_time,
            'timestamp': datetime.now().isoformat(),

            # Optional: Store full results for debugging
            '_debug': {
                'forensics_duration': forensics_result.duration,
                'analysis_duration': analysis_result.get('duration'),
                'functions_to_inspect_count': forensics_result.get_function_count()
            }
        }

        # Gap 1+6: Append cost summary and print report if tracking is enabled
        if self.router and getattr(self.config, 'track_cost', False):
            result['cost_summary'] = self.router.get_cost_summary()
            self.router.print_cost_report()

        return result

    def save_results(self, result: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """
        Save analysis results to file.

        Args:
            result: Analysis results to save
            output_path: Optional custom output path. If None, generates timestamped path.

        Returns:
            Path where results were saved
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.config.output_dir, f"analysis_{timestamp}.json")

        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Save results
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2)

        return output_path

    def analyze_and_save(self,
                        txn_link: Optional[str] = None,
                        txn_hash: Optional[str] = None,
                        chain: Optional[str] = None,
                        output_path: Optional[str] = None) -> str:
        """
        Convenience method to run analysis and save results in one call.

        Args:
            txn_link: Transaction link
            txn_hash: Transaction hash
            chain: Blockchain identifier
            output_path: Optional output file path

        Returns:
            Path where results were saved
        """
        result = self.analyze_transaction(txn_link, txn_hash, chain)
        saved_path = self.save_results(result, output_path)
        return saved_path
