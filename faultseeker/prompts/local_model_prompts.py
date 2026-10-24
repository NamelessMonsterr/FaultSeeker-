"""
Local Model Prompt Variants for FaultSeeker++

Cloud models (GPT-4, Gemini, Grok, Qwen-API) handle long, multi-part, nested JSON
prompts reliably. Local Ollama models — regardless of size (3B, 7B, 14B, 70B) —
need cleaner, single-task, explicit prompts to produce valid JSON consistently.

This module provides simplified prompt variants that are automatically swapped in
whenever an Ollama (local) model is detected.

Usage:
    from faultseeker.prompts.local_model_prompts import get_worker_prompts, get_vuln_prompts
    prompts = get_worker_prompts(is_local=True)
"""

from dataclasses import dataclass
from faultseeker.prompts.function_analysis.worker_prompts import WorkerPrompts
from faultseeker.prompts.function_analysis.vulnerability_analysis_prompts import VulnerabilityAnalysisPrompts

# Cloud model prefixes — anything NOT starting with these is treated as local
CLOUD_PREFIXES = ('gpt-', 'o1-', 'o3-', 'o4-', 'grok-', 'qwen-', 'gemini-', 'claude-')


def is_local_model(model_name: str) -> bool:
    """Return True if the model is a local Ollama model (not a cloud API)."""
    return not any(model_name.startswith(p) for p in CLOUD_PREFIXES)


@dataclass
class LocalWorkerPrompts:
    """
    Simplified WorkerPrompts for local Ollama models.
    Rules:
      - One task per prompt. Never ask for multiple JSON keys at once.
      - Always give a concrete JSON example.
      - Never use vague instructions like "be smart".
      - Keep each prompt under 400 tokens.
    """

    # ── Task selection ─────────────────────────────────────────────────
    function_call_task_selection: str = """\
You are a smart contract security analyst.
Choose ONE sub-task from the task tree to investigate next.

Task tree:
{task_tree}

Function call data (summary):
{function_call_info_summary}

Current understanding:
{current_understanding}

Return ONLY this JSON with no extra text:
{{
  "task_selected": "<sub-task number>",
  "task_description": "<one clear sentence describing what to do>",
  "information": "<the specific data from Function call data needed>",
  "additional_information": ""
}}"""

    # ── Task generation (simpler version) ──────────────────────────────
    function_call_task_generation: str = """\
You are a smart contract security analyst.
Choose ONE sub-task to investigate next.

Task tree:
{task_tree}

Function call data:
{function_call_info_summary}

Describe the task in one sentence. Return ONLY:
{{"task_description": "<one sentence>", "information": "<relevant data>"}}"""

    # ── Info processing ────────────────────────────────────────────────
    function_call_info_processing: str = """\
Analyze the following smart contract function call task.
Write a short, factual analysis. Focus only on security-relevant findings.
Do NOT repeat the input data. Be concise.

Task and data:
{selected_task}"""

    # ── Organization after function call ──────────────────────────────
    function_call_organization_function_call: str = """\
Summarize what is known about this transaction so far.
Focus on: who did what, which tokens moved, which function may be vulnerable.
Be concise (3-5 sentences max).

Function call data:
{function_call_info_summary}"""

    # ── Organization after task completion ────────────────────────────
    function_call_organization_after_task_completion: str = """\
Update the transaction summary using the new analysis result.
Keep it concise (3-5 sentences).

Current summary:
{current_understanding}

New analysis:
{selected_task}"""

    # ── Children call filtering ────────────────────────────────────────
    function_call_children_call_filtering: str = """\
List the index numbers of child function calls worth investigating for vulnerabilities.
Skip: read-only getters, ERC20 transfer, approve, balanceOf.
Return ONLY a JSON list of index numbers, e.g. [0, 2] or [] if none.

Parent function: {function_name}
Children calls:
{children_calls}"""

    # ── Retrieve additional info ───────────────────────────────────────
    retrieve_additional_info: str = '''\
Convert the requested information into this JSON format.
Only include keys that are needed.

{
  "function_call": [["<address>", "<function_name>"]],
  "children_calls": [["<address>", "<function_name>"]],
  "source_code": [["<address>", "<function_name>"]],
  "balance_change": ["<address>"]
}

Available data: {0}
Request: {1}'''

    # ── Analysis init ─────────────────────────────────────────────────
    function_analysis_init_prompt: str = """\
You are analyzing a smart contract function for vulnerabilities.
Update the task tree based on the function data.

Current task tree:
{task_tree}

Current understanding:
{current_understanding}

Function data:
{function_call_info_summary}

Return the updated task tree as plain text. No JSON needed."""

    # ── Adequacy check ────────────────────────────────────────────────
    check_analysis_adequacy: str = """\
Has the analysis gathered enough evidence to identify the vulnerable function?
Answer ONLY: Yes or No.

Current understanding:
{0}"""

    check_analysis_adequacy_alt: str = """\
Is there enough information to move to the next function?
Answer ONLY: Yes or No.

Current understanding:
{0}"""

    # ── Narrow down ───────────────────────────────────────────────────
    narrow_down_functions: str = """\
You are a smart contract security expert.
From the list below, keep only the functions most likely to contain the vulnerability.
Remove: pure getters, standard ERC20 functions, callbacks that only receive funds.
Keep: price calculation, state updates, access control, custom logic.

Functions (name: appearance count):
{function_call_to_be_inspected}

Return ONLY a JSON list of function keys to keep, e.g.:
["funcA_0xabc", "funcB_0xdef"]"""

    narrow_down_functions_with_created_contracts: str = """\
From the list below, keep only the functions most likely to be vulnerable.
{function_call_to_be_inspected}

Return ONLY a JSON list of function keys, e.g.: ["funcA_0xabc"]"""


@dataclass
class LocalVulnerabilityAnalysisPrompts:
    """
    Simplified VulnerabilityAnalysisPrompts for local Ollama models.
    """

    update_potentially_vulnerable_function: str = """\
Identify any vulnerable functions from the analysis below.
A function is vulnerable if the fault (e.g. price manipulation, reentrancy,
access control bypass) can be traced into its implementation.

Return ONLY this JSON (or {{}} if nothing found):
{{
  "<functionname>_<address>": {{
    "evidence": "<one sentence explaining why>",
    "confidence_score": <float 0.0-1.0>
  }}
}}

Rules:
- The key must be one of the exact functionname_address call ids shown in the data (for example 0xfa461e33_0x0000...). Any other key is discarded as unverifiable.
- No markdown. No extra text. JSON only.

Current understanding: {0}
Current task: {1}
Analysis result: {2}"""

    rank_potentially_vulnerable_functions: str = """\
Rank these functions from most to least likely to contain the vulnerability.

Downrank: callbacks, ERC20 wrappers, read-only getters.
Prioritize: price calculation, state updates, access control.

Return ONLY a JSON list, highest likelihood first:
["funcA_0xabc", "funcB_0xdef"]

Transaction understanding: {current_understanding}
Functions to rank: {potentially_vulnerable_functions}"""


def get_worker_prompts(model_name: str = '') -> WorkerPrompts:
    """
    Return the appropriate WorkerPrompts class based on the model.
    Local Ollama models get simplified prompts; cloud models get original prompts.
    """
    if is_local_model(model_name):
        return LocalWorkerPrompts()
    return WorkerPrompts()


def get_vuln_prompts(model_name: str = '') -> VulnerabilityAnalysisPrompts:
    """
    Return the appropriate VulnerabilityAnalysisPrompts class based on the model.
    """
    if is_local_model(model_name):
        return LocalVulnerabilityAnalysisPrompts()
    return VulnerabilityAnalysisPrompts()
