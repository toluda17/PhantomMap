"""
prompt_injection.py — Rule RULE-001

Fires when a component accepts external input and feeds it to an LLM
without a trust boundary crossing being explicitly accounted for. Direct
prompt injection via user input is the most common LLM attack vector.
"""

from typing import Any, Dict, Optional
from phantommap.models.finding import Finding, Severity
from phantommap.risk_engine.rule_base import RuleBase


class PromptInjectionRule(RuleBase):

    RULE_ID = "RULE-001"
    NAME = "Prompt Injection via External Input"
    BASE_SEVERITY = Severity.CRITICAL

    def evaluate(self, surface: Dict[str, Any]) -> Optional[Finding]:
        props = surface["properties"]

        # Fires on components that accept external input
        if surface["surface_type"] == "component":
            if props.get("accepts_external_input"):
                self.logger.debug(f"RULE-001 fired on: {surface['name']}")
                return self._make_finding(
                    finding_id="",
                    title="Prompt Injection via External Input Channel",
                    description=(
                        f"'{surface['name']}' accepts input from external, "
                        f"untrusted sources. Without strict input validation "
                        f"and prompt hardening, adversaries can craft inputs "
                        f"that override system instructions, exfiltrate context "
                        f"window data, or manipulate downstream agentic actions."
                    ),
                    affected_surface=surface["name"],
                    notes="Consider both direct injection (user input) and indirect injection (retrieved documents)."
                )

        # Also fires on data flows that cross a trust boundary
        if surface["surface_type"] == "data_flow":
            if props.get("crosses_trust_boundary"):
                self.logger.debug(f"RULE-001 fired on flow: {surface['name']}")
                return self._make_finding(
                    finding_id="",
                    title="Prompt Injection Risk Across Trust Boundary",
                    description=(
                        f"The data flow '{surface['name']}' crosses a trust "
                        f"boundary. Data originating from untrusted sources "
                        f"that reaches an LLM context window without sanitisation "
                        f"is a prompt injection vector."
                    ),
                    affected_surface=surface["name"],
                    severity=Severity.HIGH,
                    notes="Indirect prompt injection via retrieved content is particularly relevant for RAG architectures."
                )

        return None
