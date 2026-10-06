"""
Hybrid LLM Router for FaultSeeker++
Research Gap 1: Cloud Dependency + Gap 6: High Infrastructure Cost

Routes LLM queries between local (Ollama) and cloud (OpenAI) models
based on task complexity, using 3-tier classification:
  - Tier 1 (Simple): Local model only (zero API cost)
  - Tier 2 (Moderate): Local with cloud fallback
  - Tier 3 (Complex): Cloud model directly

Also tracks per-query cost for cost optimization reporting.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from faultseeker.utils.agent import OllmaAgent, GPTAgent


# Cost rates per 1M tokens (USD)
COST_RATES = {
    # OpenAI
    'gpt-4o':           {'input': 2.50,  'output': 10.00},
    'gpt-4o-mini':      {'input': 0.15,  'output': 0.60},
    'gpt-4.1':          {'input': 2.00,  'output': 8.00},
    'gpt-4.1-mini':     {'input': 0.40,  'output': 1.60},
    'gpt-4.1-nano':     {'input': 0.10,  'output': 0.40},
    'o3-mini':          {'input': 1.10,  'output': 4.40},
    # xAI Grok
    'grok-3':           {'input': 3.00,  'output': 15.00},
    'grok-3-mini':      {'input': 0.30,  'output': 0.50},
    'grok-2':           {'input': 2.00,  'output': 10.00},
    'grok-2-mini':      {'input': 0.20,  'output': 0.40},
    # Alibaba Qwen (DashScope)
    'qwen-max':         {'input': 0.40,  'output': 1.20},
    'qwen-plus':        {'input': 0.08,  'output': 0.26},
    'qwen-turbo':       {'input': 0.02,  'output': 0.06},
    'qwen-long':        {'input': 0.005, 'output': 0.02},
    # Google Gemini
    'gemini-2.0-flash': {'input': 0.10,  'output': 0.40},
    'gemini-1.5-pro':   {'input': 1.25,  'output': 5.00},
    'gemini-1.5-flash': {'input': 0.075, 'output': 0.30},
    # Local models are free
}

# Agent role → default tier mapping (from plan)
AGENT_TIER_MAP = {
    'AddressClassifier': 1,         # Simple classification
    'children_call_filtering': 1,   # Simple filtering
    'generation_agent': 2,          # Task generation (moderate)
    'organization_agent': 2,        # Info organization (moderate)
    'ranking_agent': 2,             # Function ranking (moderate)
    'reasoning_agent': 3,           # Deep analysis (complex)
    'processing_agent': 3,          # Task processing (complex)
}

# Complexity keywords for heuristic classification
COMPLEXITY_KEYWORDS = {
    'high': ['analyze', 'vulnerability', 'exploit', 'cross-contract',
             'reentrancy', 'attack', 'investigate', 'reasoning'],
    'low': ['classify', 'format', 'extract', 'parse', 'list', 'filter',
            'categorize', 'label', 'identify'],
}


@dataclass
class CostRecord:
    """Tracks cost of a single LLM query."""
    model: str
    tier: int
    is_local: bool
    input_tokens_est: int = 0
    output_tokens_est: int = 0
    cost_usd: float = 0.0
    duration_ms: float = 0.0
    fallback_used: bool = False


@dataclass
class CostSummary:
    """Aggregated cost summary across all queries."""
    total_queries: int = 0
    local_queries: int = 0
    cloud_queries: int = 0
    fallback_count: int = 0
    total_cost_usd: float = 0.0
    estimated_cloud_only_cost: float = 0.0  # What it would've cost without routing
    savings_usd: float = 0.0
    savings_percent: float = 0.0
    records: List[CostRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_queries': self.total_queries,
            'local_queries': self.local_queries,
            'cloud_queries': self.cloud_queries,
            'fallback_count': self.fallback_count,
            'total_cost_usd': round(self.total_cost_usd, 4),
            'estimated_cloud_only_cost': round(self.estimated_cloud_only_cost, 4),
            'savings_usd': round(self.savings_usd, 4),
            'savings_percent': round(self.savings_percent, 1),
        }


class HybridLLMRouter:
    """
    Intelligent LLM query router implementing 3-tier complexity-based routing.

    Integrates with FaultSeeker's existing build_agent() pattern by providing
    a route() method that selects the appropriate model for each query.
    """

    def __init__(
        self,
        local_model: str = 'llama3:8b',
        cloud_model: str = 'gpt-4o-mini',
        confidence_gate: float = 0.6,
        track_cost: bool = True,
        routing_strategy: str = 'hybrid',  # 'local-first', 'cloud-first', 'hybrid', 'cloud-only'
        ablation: Any = None,
        cost_tracker: Any = None,
    ):
        self.logger = logging.getLogger(__name__)
        self.local_model = local_model
        self.cloud_model = cloud_model
        self.confidence_gate = confidence_gate
        self.track_cost = track_cost
        self.routing_strategy = routing_strategy

        from faultseeker.research.ablation import AblationConfig
        self.ablation = ablation or AblationConfig.full_system()
        self.cost_tracker = cost_tracker

        # Cost tracking
        self.cost_summary = CostSummary()

    def select_model(
        self,
        agent_role: str = '',
        prompt_text: str = '',
        tier_override: Optional[int] = None,
        local_confidence: Optional[float] = None,
    ) -> str:
        """
        Select the appropriate model for a query.

        Args:
            agent_role: Name/role of the agent making the query
            prompt_text: The prompt text (used for heuristic classification)
            tier_override: Force a specific tier (1, 2, or 3)
            local_confidence: For Tier 2, the measured confidence (0.0–1.0) of
                the local model's response. When provided and below
                ``confidence_gate`` (θ_gate), the query escalates to the cloud
                model. ``None`` (default) preserves the old behavior: Tier 2
                goes local, escalation handled by the caller.

        Returns:
            Model name string suitable for build_agent()
        """
        # Ablation: disabling LLM routing means every query goes to the cloud
        # model, which is what "no routing" actually is. The tier heuristic is
        # bypassed entirely rather than having its score adjusted.
        if not self.ablation.enabled('llm_routing'):
            return self.cloud_model

        if self.routing_strategy == 'cloud-only':
            return self.cloud_model

        # Determine tier
        if tier_override:
            tier = tier_override
        elif agent_role in AGENT_TIER_MAP:
            tier = AGENT_TIER_MAP[agent_role]
        else:
            tier = self._classify_complexity(prompt_text)

        # Route based on tier
        if tier == 1:
            return self.local_model
        elif tier == 2:
            if self.routing_strategy == 'cloud-first':
                return self.cloud_model
            # θ_gate escalation (audit-fixes): a measured local confidence
            # below the gate escalates this query to the cloud model.
            if local_confidence is not None and local_confidence < self.confidence_gate:
                return self.cloud_model
            return self.local_model  # Local first, fallback handled by caller
        else:  # tier 3
            return self.cloud_model

    def get_tier(self, agent_role: str = '', prompt_text: str = '') -> int:
        """Get the complexity tier for a query."""
        if agent_role in AGENT_TIER_MAP:
            return AGENT_TIER_MAP[agent_role]
        return self._classify_complexity(prompt_text)

    def should_fallback_to_cloud(self, tier: int) -> bool:
        """Check if a tier 2 query should fall back to cloud."""
        return tier == 2

    def should_escalate(
        self,
        agent_role: str = '',
        tier: Optional[int] = None,
        local_confidence: float = 0.0,
    ) -> bool:
        """
        θ_gate escalation check (audit-fixes): Tier 2 queries escalate to the
        cloud model when the measured local confidence falls below
        ``confidence_gate``. Tiers 1 and 3 never escalate through this path
        (Tier 1 is always local, Tier 3 is always cloud).
        """
        resolved = tier if tier is not None else self.get_tier(agent_role)
        return resolved == 2 and local_confidence < self.confidence_gate

    def escalate_agent(self, agent: Any) -> Any:
        """
        Rebuild an agent created by :func:`build_routed_agent` with the cloud
        model, preserving its system prompt and role. Used for Tier 2 θ_gate
        escalation retries.
        """
        from faultseeker.utils.agent import build_provider_agent
        role = getattr(agent, 'agent_role', '')
        system_prompt = getattr(agent, 'system_prompt', '')
        if not system_prompt:
            try:
                system_prompt = (agent.memory or [{}])[0].get('content', '')
            except Exception:
                system_prompt = ''
        new_agent = build_provider_agent(system_prompt, self.cloud_model)
        setattr(new_agent, 'router', self)
        setattr(new_agent, 'agent_role', role)
        setattr(new_agent, 'escalated_from_local', True)
        return new_agent

    def record_query(
        self,
        model: str,
        tier: int,
        prompt_length: int = 0,
        response_length: int = 0,
        duration_ms: float = 0,
        fallback_used: bool = False,
        agent_role: str = '',
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
    ):
        """Record a query for cost tracking."""
        if not self.track_cost:
            return

        is_local = self._is_local_model(model)

        # Use actual token counts if provided, otherwise estimate (~4 chars per token)
        if input_tokens is None:
            input_tokens = prompt_length // 4
        if output_tokens is None:
            output_tokens = response_length // 4

        # Calculate cost
        cost = 0.0
        if not is_local and model in COST_RATES:
            rates = COST_RATES[model]
            cost = (input_tokens * rates['input'] + output_tokens * rates['output']) / 1_000_000

        record = CostRecord(
            model=model,
            tier=tier,
            is_local=is_local,
            input_tokens_est=input_tokens,
            output_tokens_est=output_tokens,
            cost_usd=cost,
            duration_ms=duration_ms,
            fallback_used=fallback_used,
        )

        self.cost_summary.records.append(record)
        self.cost_summary.total_queries += 1
        self.cost_summary.total_cost_usd += cost

        if is_local:
            self.cost_summary.local_queries += 1
        else:
            self.cost_summary.cloud_queries += 1
        if fallback_used:
            self.cost_summary.fallback_count += 1

        # Bridge into the research CostTracker so paper section 6.7 numbers come
        # from real calls instead of hardcoded constants.
        if self.cost_tracker is not None:
            self.cost_tracker.record_llm_call(
                stage=agent_role or 'llm_query',
                tier='local' if is_local else 'cloud',
                model=model,
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
                latency_secs=duration_ms / 1000.0,
            )

        # Estimate what cloud-only would cost
        if model in COST_RATES:
            cloud_rates = COST_RATES.get(self.cloud_model, COST_RATES.get('gpt-4o-mini', {}))
            cloud_cost = (input_tokens * cloud_rates.get('input', 0.15) +
                         output_tokens * cloud_rates.get('output', 0.60)) / 1_000_000
            self.cost_summary.estimated_cloud_only_cost += cloud_cost
        elif is_local:
            # If local, the cloud alternative would have cost something
            cloud_rates = COST_RATES.get(self.cloud_model, COST_RATES.get('gpt-4o-mini', {}))
            cloud_cost = (input_tokens * cloud_rates.get('input', 0.15) +
                         output_tokens * cloud_rates.get('output', 0.60)) / 1_000_000
            self.cost_summary.estimated_cloud_only_cost += cloud_cost

    def get_cost_summary(self) -> Dict[str, Any]:
        """Get the current cost summary."""
        s = self.cost_summary
        s.savings_usd = s.estimated_cloud_only_cost - s.total_cost_usd
        if s.estimated_cloud_only_cost > 0:
            s.savings_percent = (s.savings_usd / s.estimated_cloud_only_cost) * 100
        return s.to_dict()

    def print_cost_report(self):
        """Print a formatted cost report to stdout."""
        summary = self.get_cost_summary()
        print("\n💰 Cost Report:")
        print(f"   Queries: {summary['total_queries']} total "
              f"({summary['local_queries']} local, {summary['cloud_queries']} cloud)")
        print(f"   Fallbacks: {summary['fallback_count']}")
        print(f"   Actual cost:     ${summary['total_cost_usd']:.4f}")
        print(f"   Cloud-only cost: ${summary['estimated_cloud_only_cost']:.4f}")
        print(f"   Savings:         ${summary['savings_usd']:.4f} "
              f"({summary['savings_percent']:.0f}%)")

    # ─── Private ──────────────────────────────────────────────────────

    def _classify_complexity(self, prompt_text: str) -> int:
        """Heuristic complexity classification based on prompt content."""
        text_lower = prompt_text.lower()
        prompt_len = len(prompt_text)

        high_score = sum(1 for kw in COMPLEXITY_KEYWORDS['high'] if kw in text_lower)
        low_score = sum(1 for kw in COMPLEXITY_KEYWORDS['low'] if kw in text_lower)

        # Long prompts with complex keywords → tier 3
        if (high_score >= 2 and prompt_len > 2000) or high_score >= 3:
            return 3
        # Short prompts with simple keywords → tier 1
        elif low_score >= 2 and prompt_len < 1000:
            return 1
        # Everything else → tier 2
        else:
            return 2

    def _is_local_model(self, model: str) -> bool:
        """Check if a model is a local model (not a cloud API)."""
        cloud_prefixes = ('gpt-', 'o1-', 'o3-', 'o4-',
                          'claude-', 'grok-', 'qwen-', 'gemini-')
        return not any(model.startswith(p) for p in cloud_prefixes)


def build_routed_agent(
    model_name: str,
    router: Optional[HybridLLMRouter] = None,
    agent_role: str = '',
    system_prompt: str = '',
) -> Any:
    """
    Build an LLM agent with optional routing.

    Drop-in enhancement for FaultSeeker's build_agent() function.
    If a router is provided, it selects the model; otherwise uses the
    given model_name directly.

    Uses build_provider_agent() to correctly route:
      gpt-*, o1-*, o3-*, o4-*  → GPTAgent  (OpenAI)
      gemini-*                  → UniversalAgent (Google)
      grok-*                   → UniversalAgent (xAI)
      qwen-*                   → UniversalAgent (Alibaba)
      <anything else>           → OllmaAgent (local Ollama)
    """
    from faultseeker.utils.agent import build_provider_agent

    if router:
        selected_model = router.select_model(agent_role=agent_role)
    else:
        selected_model = model_name

    # Guard: never pass an empty model string
    if not selected_model or not selected_model.strip():
        selected_model = router.local_model if router else 'phi3:mini'

    agent = build_provider_agent(system_prompt, selected_model)
    if router:
        setattr(agent, 'router', router)
        setattr(agent, 'agent_role', agent_role)
        setattr(agent, 'system_prompt', system_prompt)
    return agent
