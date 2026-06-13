"""
mapper.py

Orchestrates framework annotation across all findings. For each finding,
it calls the OWASP and ATLAS mappers to attach references, then calls
compute_score() now that the full picture is available.

Scoring happens here rather than in the risk engine because the composite
score accounts for how many frameworks flag a finding -- that information
only exists after annotation is complete.
"""

from typing import List
from phantommap.models.finding import Finding
from phantommap.framework_mapper.owasp_llm import get_owasp_references
from phantommap.framework_mapper.mitre_atlas import get_atlas_references
from phantommap.logger import get_logger

logger = get_logger(__name__)


def annotate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Annotates each finding with OWASP and ATLAS references, then
    computes its composite score. Returns the same list, mutated in place.
    """
    logger.info(f"Annotating {len(findings)} findings with framework references")

    for finding in findings:
        finding.owasp_references = get_owasp_references(finding.rule_id)
        finding.atlas_references = get_atlas_references(finding.rule_id)
        finding.compute_score()

        logger.debug(
            f"{finding.id} | score={finding.score} | "
            f"owasp={[r.id for r in finding.owasp_references]} | "
            f"atlas={[r.id for r in finding.atlas_references]}"
        )

    logger.info("Framework annotation complete")
    return findings
