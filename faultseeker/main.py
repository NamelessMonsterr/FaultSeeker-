import argparse
import json
import os
import re
from datetime import datetime

from faultseeker.forensics.result import compute_priority_breakdown, extract_reentrancy_analysis


def banner():
    print("\n" + "=" * 60)
    print("FaultSeeker - Blockchain Transaction Analyzer")
    print("=" * 60)


def _resolve_output(output_dir: str, output_path: str = None) -> tuple[str, str]:
    if output_path:
        return os.path.dirname(output_path) or ".", output_path

    if output_dir.lower().endswith(".json"):
        return os.path.dirname(output_dir) or ".", output_dir

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return output_dir, os.path.join(output_dir, f"analysis_{timestamp}.json")


def _parse_offline_txn_link(txn_link: str) -> tuple[str, str]:
    """Parse a supported explorer link without importing the live pipeline."""
    match = re.search(r"(0x[0-9a-fA-F]{64})", txn_link)
    if not match:
        raise ValueError(f"Could not extract transaction hash from link: {txn_link}")
    link = txn_link.lower()
    chain_map = (
        ("bscscan", "bsc"), ("bsc", "bsc"),
        ("polygonscan", "polygon"), ("polygon", "polygon"),
        ("arbiscan", "arbitrum"), ("arbitrum", "arbitrum"),
        ("optimistic.etherscan", "optimism"), ("optimism", "optimism"),
        ("snowtrace", "avalanche"), ("avalanche", "avalanche"),
        ("basescan", "base"), ("base", "base"),
        ("ftmscan", "fantom"), ("fantom", "fantom"),
        ("explorer.zksync", "zksync"), ("zksync", "zksync"),
        ("gnosisscan", "gnosis"), ("gnosis", "gnosis"),
        ("etherscan", "eth"), ("eth", "eth"),
    )
    for keyword, chain in chain_map:
        if keyword in link:
            return match.group(1), chain
    raise ValueError(f"The blockchain network is not supported: {txn_link}")


def _offline_stage1_result(txn_hash: str, chain: str, cache_dir: str) -> dict:
    """Build a deterministic no-LLM Stage-1 report from local data only.

    Offline mode deliberately does not instantiate the normal pipeline.  A
    previously saved Stage-1 forensics report is used when available; without
    one, the returned report is an explicit deterministic demo/triage result.
    No RPC, explorer, model, or provider is contacted from this path.
    """
    cache_path = os.path.join(cache_dir, "forensics", f"{txn_hash}.json")
    cached = None
    if os.path.isfile(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                candidate = json.load(f)
            if isinstance(candidate, dict):
                transaction = candidate.get("transaction", {}) or {}
                cached_hash = transaction.get("hash", "")
                cached_chain = transaction.get("chain", "")
                if (isinstance(cached_hash, str) and isinstance(cached_chain, str)
                        and cached_hash.lower() == txn_hash.lower()
                        and cached_chain.lower() == chain.lower()):
                    cached = candidate
        except (OSError, ValueError, TypeError):
            cached = None

    if cached is None:
        signals = {
            "offline_demo": True,
            "data_source": "local_input_only",
            "coverage": {
                "trace_complete": False,
                "token_flow_complete": False,
                "multi_tx_context_complete": False,
            },
        }
        transaction_understanding = (
            "No local Stage-1 cache was found; deterministic demo triage only."
        )
        matched_rule = ""
        verdict = "UNCERTAIN"
        confidence = 0.0
        ranked_functions = []
        attackers = []
        victims = []
        balance_changes = {}
        functions_to_inspect = {}
        cache_used = False
    else:
        classification = cached.get("classification", {}) or {}
        attack = cached.get("attack_analysis", {}) or {}
        function_analysis = cached.get("function_analysis", {}) or {}
        signals = classification.get("signals", {}) or {}
        matched_rule = classification.get("matched_rule", "")
        verdict = classification.get("rule_verdict", "UNKNOWN")
        confidence = float(classification.get("rule_confidence", 0.0) or 0.0)
        transaction_understanding = (
            "Deterministic Stage-1 triage loaded from the local forensics cache."
        )
        functions_to_inspect = function_analysis.get("functions_to_inspect", {}) or {}
        ranked_functions = []
        for category in (
            "flashloan_callback",
            "function_name_with_hash",
            "call_with_created_contract",
            "function_name_with_hash_children",
            "others",
        ):
            ranked_functions.extend(functions_to_inspect.get(category, []) or [])
        attackers = attack.get("potential_attackers", []) or []
        victims = attack.get("potential_victims", []) or []
        balance_changes = attack.get("balance_changes", {}) or {}
        cache_used = True

    priority = compute_priority_breakdown(signals, exploitability_score=confidence)
    return {
        "transaction_hash": txn_hash,
        "chain": chain,
        "analysis_mode": "offline-no-llm",
        "analysis_status": "stage1_complete",
        "stage_completed": "stage1",
        "stage2_bypassed": True,
        "analysis_complete": True,
        "cache_used": cache_used,
        "verdict": verdict,
        "rule_verdict": verdict,
        "rule_confidence": confidence,
        "matched_rule": matched_rule,
        "reclassification_locked": False,
        "ranked_suspicious_functions": ranked_functions,
        "potentially_vulnerable_functions": [],
        "transaction_understanding": transaction_understanding,
        "scored_functions": [],
        "signals": signals,
        "evidence_cards": [],
        "rejected_findings": [],
        "finding_count": 0,
        "reentrancy": extract_reentrancy_analysis(signals),
        "priority": priority,
        "priority_score": priority["total"],
        "potential_attackers": attackers,
        "potential_victims": victims,
        "balance_changes": balance_changes,
        "functions_to_inspect": functions_to_inspect,
        "analyst_feedback": [],
        "analysis_context": {"offline": True, "cache_path": cache_path if cache_used else None},
        "llm_cost": 0.0,
        "query_records": [],
        "duration": 0.0,
        "limitations": [
            "No LLM or provider was constructed or called.",
            "Stage 2 function analysis was intentionally skipped.",
            "No network/RPC request is made by offline mode; uncached input is demo triage only.",
        ],
    }


def _no_llm_stage1_result(txn_hash: str, chain: str, cache_dir: str) -> dict:
    """Run deterministic Stage 1 through free/public acquisition only.

    This path constructs the real forensics orchestrator but never constructs
    Stage 2 agents or sends an LLM request. It is intended for live demos.
    """
    # The repository's RPC module loads `.env` at import time. Disable that
    # behavior for this mode so a demo can never silently select a configured
    # paid endpoint or model credential; only built-in public RPC fallbacks are
    # eligible here.
    os.environ["PYTHON_DOTENV_DISABLED"] = "true"
    from faultseeker.forensics.orchestrator import ForensicsOrchestrator

    orchestrator = ForensicsOrchestrator(
        model="offline-no-llm",
        cache_dir=os.path.join(cache_dir, "forensics"),
    )
    forensics_result, txn_seq, txn_info = orchestrator.run(txn_hash, chain)
    if not forensics_result:
        raise RuntimeError(
            "Stage 1 could not acquire or analyze this transaction with the "
            "available free explorer/RPC providers"
        )

    result = forensics_result.to_dict(include_internal=False)
    result.update({
        "analysis_mode": "no-llm-free-rpc",
        "analysis_status": "stage1_complete",
        "stage_completed": "stage1",
        "stage2_bypassed": True,
        "analysis_complete": True,
        "rpc_source": (txn_info or {}).get("_source", "unknown"),
        "trace_coverage": (txn_seq or {}).get("trace_coverage", {}),
        "llm_cost": 0.0,
        "query_records": [],
        "limitations": [
            "No LLM or provider was constructed or called.",
            "Stage 2 function analysis was intentionally skipped.",
            "Function localization and calibrated Stage 3 scores are not present.",
        ],
    })
    return result


def main(
    txn_link: str = None,
    txn_hash: str = None,
    chain: str = None,
    forensics_model: str = None,
    function_analysis_model: str = None,
    cache_dir: str = "./data/cache",
    output_dir: str = "./data/output",
    output_path: str = None,
    explain: bool = False,
    auto_route: bool = False,
    track_cost: bool = False,
    local_model: str = None,
    human_in_loop: bool = False,
    offline: bool = False,
    no_llm: bool = False,
):
    banner()
    print("\nTransaction Information:")
    if txn_link:
        print(f"   * Link: {txn_link}")
    elif txn_hash and chain:
        print(f"   * Hash: {txn_hash}")
        print(f"   * Chain: {chain.upper()}")
    else:
        raise ValueError("Either txn_link or both txn_hash and chain must be provided.")

    if offline and txn_link:
        txn_hash, chain = _parse_offline_txn_link(txn_link)
    if offline:
        chain = (chain or "").lower()
        output_dir, output_path = _resolve_output(output_dir, output_path)
        os.makedirs(output_dir, exist_ok=True)
        print("\nOffline/no-LLM mode: running deterministic Stage 1 only")
        result = _offline_stage1_result(txn_hash, chain, cache_dir)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"   Results saved to: {output_path}")
        print("   Stage 2 skipped; no model, provider, RPC, or explorer call was made")
        return result

    if no_llm:
        chain = (chain or "").lower()
        output_dir, output_path = _resolve_output(output_dir, output_path)
        os.makedirs(output_dir, exist_ok=True)
        print("\nNo-LLM mode: running real deterministic Stage 1 via free/public RPC")
        result = _no_llm_stage1_result(txn_hash, chain, cache_dir)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"   Results saved to: {output_path}")
        print("   Stage 2 skipped; no model/provider call was made")
        return result

    from faultseeker.core.auto_model_selector import (
        interactive_model_selection,
        print_model_selection,
    )
    from faultseeker.core.config import FaultSeekerConfig
    from faultseeker.core.pipeline import FaultSeekerPipeline

    auto_route_enabled = auto_route
    local_model_name = local_model
    cloud_model_name = None

    if not forensics_model or not function_analysis_model:
        model_config = interactive_model_selection()
        print_model_selection(model_config)

        local_model_name = model_config.get("local_model") or local_model_name
        actual_cloud = model_config.get("actual_cloud_model")

        if model_config.get("use_hybrid") and actual_cloud:
            forensics_model = forensics_model or local_model_name
            function_analysis_model = function_analysis_model or actual_cloud
            cloud_model_name = actual_cloud
            auto_route_enabled = True
            print(
                "   Hybrid mode: "
                f"Stage 1 -> {forensics_model} (local), "
                f"Stage 2 -> {function_analysis_model} (cloud)"
            )
        else:
            single = model_config["cloud_model"]
            forensics_model = forensics_model or single
            function_analysis_model = function_analysis_model or single
    elif auto_route_enabled:
        cloud_model_name = function_analysis_model

    output_dir, output_path = _resolve_output(output_dir, output_path)
    os.makedirs(output_dir, exist_ok=True)

    print("\nConfiguration:")
    print(f"   * Forensics Model: {forensics_model}")
    print(f"   * Function Analysis Model: {function_analysis_model}")
    if auto_route_enabled:
        print("   * Routing: Hybrid (local Tier 1/2, cloud Tier 3)")
    if track_cost:
        print("   * Cost Tracking: enabled")
    if human_in_loop:
        print("   * Human-in-the-loop: enabled")
    print(f"   * Cache Directory: {cache_dir}")
    print(f"   * Output Directory: {output_dir}")
    print(f"   * Output File: {output_path}")

    print("\nInitializing analysis pipeline...")
    pipeline = FaultSeekerPipeline(
        config=FaultSeekerConfig(
            forensics_model=forensics_model,
            function_analysis_model=function_analysis_model,
            cloud_model=cloud_model_name or "",
            cache_dir=cache_dir,
            output_dir=output_dir,
            auto_route=auto_route_enabled,
            local_model=local_model_name or forensics_model,
            routing_strategy="hybrid",
            track_cost=track_cost,
            human_in_loop=human_in_loop,
        )
    )
    print("   Pipeline initialized successfully")

    result = pipeline.analyze_transaction(
        txn_link=txn_link,
        txn_hash=txn_hash,
        chain=chain,
    )

    print("\nSaving analysis results...")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"   Results saved to: {output_path}")

    try:
        from faultseeker.utils.explorer_provider import print_explorer_stats
        from faultseeker.utils.rpc_provider import print_provider_stats

        print_provider_stats(chain)
        print_explorer_stats(chain)
    except Exception:
        pass

    if explain and result.get("evidence_cards"):
        print(f"\nEvidence Cards ({len(result['evidence_cards'])} findings):")
        print("-" * 60)
        for i, card in enumerate(result["evidence_cards"], 1):
            sig = card.get("function_signature", {})
            conf = card.get("confidence", {})
            print(f"\n  [{i}] {sig.get('function', '?')} @ {sig.get('address', '?')[:10]}...")
            print(f"      Confidence: {conf.get('overall', 0):.1%} ({conf.get('level', '?')})")
            components = conf.get("components", {})
            if components:
                print(f"      Pattern Match:   {components.get('pattern_match', 0):.1%}")
                print(f"      Code Evidence:   {components.get('code_evidence', 0):.1%}")
                print(f"      Txn Consistency: {components.get('txn_consistency', 0):.1%}")
                print(f"      LLM Confidence:  {components.get('llm_confidence', 0):.1%}")
            evidence = card.get("evidence", [])
            if evidence:
                print("      Evidence:")
                for ev in evidence[:3]:
                    print(f"        * {str(ev)[:80]}")
        print("-" * 60)

    print("\nAnalysis completed successfully!")
    print("=" * 60 + "\n")

    return result


def run_analysis(
    txn_hash: str,
    chain: str,
    model: str = "gpt-4o-mini",
    local_model: str = None,
    cache_dir: str = "./data/cache",
    output_dir: str = "./data/output",
    explain: bool = False,
    track_cost: bool = False,
    human_in_loop: bool = False,
    offline: bool = False,
    no_llm: bool = False,
) -> dict:
    """Importable entry point for eval scripts and cross-chain runs."""
    forensics_model = local_model if local_model else model
    return main(
        txn_hash=txn_hash,
        chain=chain,
        forensics_model=forensics_model,
        function_analysis_model=model,
        cache_dir=cache_dir,
        output_dir=output_dir,
        explain=explain,
        auto_route=bool(local_model),
        track_cost=track_cost,
        local_model=local_model,
        human_in_loop=human_in_loop,
        offline=offline,
        no_llm=no_llm,
    )


def main_cli():
    parser = argparse.ArgumentParser(
        description="FaultSeeker: LLM-Empowered Framework for Blockchain Transaction Forensics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-txn_link", help="Transaction link to analyze")
    parser.add_argument("-txn_hash", help="Transaction hash to analyze")
    parser.add_argument(
        "-chain",
        default="eth",
        help="Chain identifier (eth, bsc, polygon, optimism, arbitrum, avalanche, fantom, base)",
    )
    parser.add_argument(
        "-forensics_model",
        default=None,
        help="Model for Stage 1 forensics analysis (default: auto-detect)",
    )
    parser.add_argument(
        "-function_analysis_model",
        default=None,
        help="Model for Stage 2 function analysis (default: auto-detect)",
    )
    parser.add_argument(
        "-output",
        default="./data/output",
        help="Output directory or .json file path",
    )
    parser.add_argument(
        "-cache",
        default="./data/cache",
        help="Cache directory for intermediate results",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        default=False,
        help="Display detailed evidence cards with confidence scores",
    )
    parser.add_argument(
        "--auto-route",
        action="store_true",
        default=False,
        help="Enable hybrid LLM routing between local and cloud models",
    )
    parser.add_argument(
        "--track-cost",
        action="store_true",
        default=False,
        help="Track and display LLM API costs",
    )
    parser.add_argument(
        "--local-model",
        default="llama3:8b",
        help="Local model for Ollama when using --auto-route",
    )
    parser.add_argument(
        "--human-in-loop",
        action="store_true",
        default=False,
        help="Enable analyst interaction at key checkpoints",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        default=False,
        help="Strict local-only demo mode: use a local Stage-1 cache/input and skip Stage 2",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        default=False,
        help="No-LLM live demo mode: use free/public acquisition for deterministic Stage 1 only",
    )

    args = parser.parse_args()

    if not args.txn_link and not (args.txn_hash and args.chain):
        parser.error("Either -txn_link or both -txn_hash and -chain must be provided")

    try:
        main(
            txn_link=args.txn_link,
            txn_hash=args.txn_hash,
            chain=args.chain,
            forensics_model=args.forensics_model,
            function_analysis_model=args.function_analysis_model,
            cache_dir=args.cache,
            output_dir=args.output,
            explain=args.explain,
            auto_route=args.auto_route,
            track_cost=args.track_cost,
            local_model=args.local_model,
            human_in_loop=args.human_in_loop,
            offline=args.offline,
            no_llm=args.no_llm,
        )
    except Exception as e:
        print(f"\nError: {e}")
        import traceback

        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main_cli()
