"""
insecure_output.py — Rule RULE-004

Fires when LLM output flows into a system with write access and no
human review. Unsanitised LLM output used in downstream systems can
enable injection attacks -- XSS, SQLi, or command injection -- via
model responses.
"""

from typing import Any, Dict, Optional
from phantommap.models.finding import Finding, Severity
from phantommap.risk_engine.rule_base import RuleBase


class InsecureOutputRule(RuleBase):

    RULE_ID = "RULE-004"
    NAME = "Insecure Output Handling"
    BASE_SEVERITY = Severity.HIGH

    def evaluate(self, surface: Dict[str, Any]) -> Optional[Finding]:
        props = surface["properties"]

        # Fires on data flows from an LLM into a system with write capability
        if surface["surface_type"] == "data_flow":
            destination = props.get("destination", "").lower()
            source = props.get("source", "").lower()

            is_from_llm = "llm" in source or "model" in source
            goes_to_writable = any(
                term in destination
                for term in ["crm", "database", "db", "backend", "api", "storage"]
            )

            if is_from_llm and goes_to_writable and not props.get("human_in_the_loop"):
                self.logger.debug(f"RULE-004 fired on: {surface['name']}")
                return self._make_finding(
                    finding_id="",
                    title="Insecure Output Handling — LLM Output Written Without Sanitisation",
                    description=(
                        f"The flow '{surface['name']}' carries LLM output into "
                        f"a downstream system without human review. If LLM responses "
                        f"are written directly to databases, APIs, or rendered in "
                        f"interfaces without sanitisation, they can carry injected "
                        f"payloads that execute in the target context."
                    ),
                    affected_surface=surface["name"],
                    notes="Treat all LLM output as untrusted. Apply context-appropriate encoding and validation before use in downstream systems."
                )

        return None
