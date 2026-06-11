"""
excessive_agency.py — Rule RULE-003

Fires when an LLM-driven integration has write access and there's no
human in the loop. This is the defining risk of agentic architectures --
the LLM can take real-world actions without human review or approval.
"""

from typing import Any, Dict, Optional
from phantommap.models.finding import Finding, Severity
from phantommap.risk_engine.rule_base import RuleBase


class ExcessiveAgencyRule(RuleBase):

    RULE_ID = "RULE-003"
    NAME = "Excessive Agency — Unreviewed Real-World Actions"
    BASE_SEVERITY = Severity.CRITICAL

    def evaluate(self, surface: Dict[str, Any]) -> Optional[Finding]:
        props = surface["properties"]

        # Fires on integrations with write access and no human oversight
        if surface["surface_type"] == "integration":
            if props.get("has_write_access") and not props.get("human_in_the_loop"):
                self.logger.debug(f"RULE-003 fired on: {surface['name']}")
                return self._make_finding(
                    finding_id="",
                    title="Excessive Agency — Write Access Without Human Oversight",
                    description=(
                        f"'{surface['name']}' has write access and the application "
                        f"has no human-in-the-loop review before actions execute. "
                        f"An adversary who influences LLM outputs via prompt injection "
                        f"can trigger unintended writes, deletions, or state changes "
                        f"in this system."
                    ),
                    affected_surface=surface["name"],
                    notes="Apply least-privilege to integration service accounts. Introduce confirmation steps before destructive or irreversible actions."
                )

        return None
