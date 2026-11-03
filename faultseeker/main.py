import argparse
import json
import os
import sys
from datetime import datetime

from faultseeker.core.auto_model_selector import (
    interactive_model_selection,
    print_model_selection,
)
from faultseeker.core.config import FaultSeekerConfig
from faultseeker.core.pipeline import FaultSeekerPipeline


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
):
    # Standard JSON codecs and deepcopy still recurse through nested dict/list
    # containers, even though trace-specific traversal is iterative. Establish
    # application capacity before retrieval/cache/report processing, rather than
    # relying on the historical function-analyzer import side effect. This is
    # process-wide and is never temporarily reset while worker threads run.
    # The supported 1,024-frame boundary is tested; arbitrary depth is not.
    if sys.getrecursionlimit() < 20000:
        sys.setrecursionlimit(20000)
    banner()
    print("\nTransaction Information:")
    if txn_link:
        print(f"   * Link: {txn_link}")
    elif txn_hash and chain:
        print(f"   * Hash: {txn_hash}")
        print(f"   * Chain: {chain.upper()}")
    else:
        raise ValueError("Either txn_link or both txn_hash and chain must be provided.")

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
        )
    except Exception as e:
        print(f"\nError: {e}")
        import traceback

        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main_cli()
