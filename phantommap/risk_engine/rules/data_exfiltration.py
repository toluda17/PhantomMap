"""
data_exfiltration.py — Rule RULE-002

Fires when sensitive data flows to an untrusted external integration
(e.g. a third-party LLM provider). The LLM may retain, log, or leak
this data outside organisational control.
"""

from typing import Any, Dict, Optional
from phantommap.models.finding import Finding, Severity
from phantommap.risk_engine.rule_base import RuleBase


class DataExfiltrationRule(RuleBase):

    RULE_ID = "RULE-002"
    NAME = "Sensitive Data Exfiltration via LLM"
    BASE_SEVERITY = Severity.HIGH

    def evaluate(self, surface: Dict[str, Any]) -> Optional[Finding]:
        props = surface["properties"]

        # Fires on data flows carrying sensitive data across a trust boundary
        if surface["surface_type"] == "data_flow":
            if props.get("carries_sensitive_data") and props.get("crosses_trust_boundary"):
                self.logger.debug(f"RULE-002 fired on: {surface['name']}")
                return self._make_finding(
                    finding_id="",
                    title="Sensitive Data Transmitted Across Trust Boundary to LLM",
                    description=(
                        f"The flow '{surface['name']}' carries sensitive data "
                        f"across a trust boundary. Data sent to external LLM "
                        f"providers may be logged, used for training, or exposed "
                        f"through the provider's own vulnerabilities."
                    ),
                    affected_surface=surface["name"],
                    notes="Review provider data retention and training opt-out policies. Consider data minimisation before LLM submission."
                )

        # Fires on untrusted LLM provider integrations
        if surface["surface_type"] == "integration":
            if props.get("type") == "llm_provider" and not props.get("trusted"):
                self.logger.debug(f"RULE-002 fired on integration: {surface['name']}")
                return self._make_finding(
                    finding_id="",
                    title="Untrusted LLM Provider May Expose Submitted Data",
                    description=(
                        f"'{surface['name']}' is an external LLM provider not "
                        f"under organisational control. Any data submitted in "
                        f"prompts — including retrieved documents, user messages, "
                        f"and system instructions — is processed outside the "
                        f"organisation's security boundary."
                    ),
                    affected_surface=surface["name"],
                    severity=Severity.HIGH,
                    notes="Evaluate provider SOC 2 compliance, data processing agreements, and prompt logging policies."
                )

        return None
