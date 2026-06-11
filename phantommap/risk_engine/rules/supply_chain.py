"""
supply_chain.py — Rule RULE-005

Fires on any external integration not under organisational control.
Third-party model providers, managed vector databases, and external
plugins introduce supply chain risk -- their security posture, data
handling, and model behaviour are outside your control.
"""

from typing import Any, Dict, Optional
from phantommap.models.finding import Finding, Severity
from phantommap.risk_engine.rule_base import RuleBase


class SupplyChainRule(RuleBase):

    RULE_ID = "RULE-005"
    NAME = "Supply Chain / Third-Party Integration Risk"
    BASE_SEVERITY = Severity.MEDIUM

    def evaluate(self, surface: Dict[str, Any]) -> Optional[Finding]:
        props = surface["properties"]

        # Fires on any untrusted external integration
        if surface["surface_type"] == "integration":
            if not props.get("trusted"):
                self.logger.debug(f"RULE-005 fired on: {surface['name']}")
                return self._make_finding(
                    finding_id="",
                    title="Third-Party Integration Introduces Supply Chain Risk",
                    description=(
                        f"'{surface['name']}' is an external integration not "
                        f"fully under organisational control. The security, "
                        f"availability, and behaviour of this service — including "
                        f"model updates, API changes, and data handling practices "
                        f"— can change without notice and may introduce new risks."
                    ),
                    affected_surface=surface["name"],
                    notes="Maintain a software bill of materials (SBOM) for AI components. Monitor provider security advisories and review data processing agreements."
                )

        return None
