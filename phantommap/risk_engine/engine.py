"""
engine.py

Orchestrates rule evaluation across all extracted surfaces. Loads every
rule, runs each one against every surface, collects findings, and assigns
sequential IDs. Scoring is deferred -- findings are scored after the
framework mapper has annotated them.
"""

from typing import List, Dict, Any
from phantommap.models.finding import Finding
from phantommap.risk_engine.rules.prompt_injection import PromptInjectionRule
from phantommap.risk_engine.rules.data_exfiltration import DataExfiltrationRule
from phantommap.risk_engine.rules.excessive_agency import ExcessiveAgencyRule
from phantommap.risk_engine.rules.insecure_output import InsecureOutputRule
from phantommap.risk_engine.rules.supply_chain import SupplyChainRule
from phantommap.logger import get_logger

logger = get_logger(__name__)

RULES = [
    PromptInjectionRule(),
    DataExfiltrationRule(),
    ExcessiveAgencyRule(),
    InsecureOutputRule(),
    SupplyChainRule(),
]


def run_rules(surfaces: List[Dict[str, Any]]) -> List[Finding]:
    """
    Runs all rules against all surfaces and returns a deduplicated,
    sequentially ID'd list of findings.
    """
    findings = []
    finding_counter = 1

    for surface in surfaces:
        for rule in RULES:
            result = rule.evaluate(surface)
            if result is not None:
                result.id = f"FIND-{finding_counter:03d}"
                findings.append(result)
                finding_counter += 1
                logger.info(f"{result.id} | {result.severity.value} | {result.title}")

    logger.info(f"Risk engine complete — {len(findings)} findings identified")
    return findings
