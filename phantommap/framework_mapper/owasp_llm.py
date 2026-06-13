"""
owasp_llm.py

Loads the OWASP LLM Top 10 reference data and maps PhantomMap rule IDs
to the relevant OWASP entries. Called by the framework mapper to annotate
findings with standardised OWASP references.
"""

import json
from typing import List, Dict
from phantommap.config import OWASP_DATA_PATH
from phantommap.models.finding import OWASPReference
from phantommap.logger import get_logger

logger = get_logger(__name__)

# Maps rule IDs to the OWASP LLM Top 10 entry IDs they correspond to.
# A rule can map to multiple OWASP entries if it covers overlapping risks.
RULE_TO_OWASP: Dict[str, List[str]] = {
    "RULE-001": ["LLM01:2025", "LLM07:2025"],
    "RULE-002": ["LLM02:2025", "LLM06:2025"],
    "RULE-003": ["LLM06:2025"],
    "RULE-004": ["LLM05:2025"],
    "RULE-005": ["LLM03:2025"],
}


def load_owasp_data() -> Dict[str, dict]:
    """Loads the OWASP LLM Top 10 JSON and returns a dict keyed by entry ID."""
    with open(OWASP_DATA_PATH, "r") as f:
        data = json.load(f)
    return {entry["id"]: entry for entry in data["entries"]}


def get_owasp_references(rule_id: str) -> List[OWASPReference]:
    """
    Returns a list of OWASPReference objects for the given rule ID.
    Returns an empty list if the rule has no OWASP mapping.
    """
    owasp_data = load_owasp_data()
    entry_ids = RULE_TO_OWASP.get(rule_id, [])

    references = []
    for entry_id in entry_ids:
        entry = owasp_data.get(entry_id)
        if entry:
            references.append(OWASPReference(
                id=entry["id"],
                name=entry["name"],
                url=entry["url"]
            ))
        else:
            logger.warning(f"OWASP entry {entry_id} not found in data file")

    return references
