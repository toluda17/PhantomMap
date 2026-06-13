"""
mitre_atlas.py

Loads the MITRE ATLAS reference data and maps PhantomMap rule IDs to
the relevant ATLAS techniques. Called by the framework mapper to annotate
findings with standardised ATLAS references.
"""

import json
from typing import List, Dict
from phantommap.config import ATLAS_DATA_PATH
from phantommap.models.finding import ATLASReference
from phantommap.logger import get_logger

logger = get_logger(__name__)

# Maps rule IDs to the MITRE ATLAS technique IDs they correspond to.
RULE_TO_ATLAS: Dict[str, List[str]] = {
    "RULE-001": ["AML.T0051", "AML.T0054", "AML.T0043"],
    "RULE-002": ["AML.T0037", "AML.T0040", "AML.T0044"],
    "RULE-003": ["AML.T0047", "AML.T0051"],
    "RULE-004": ["AML.T0043", "AML.T0047"],
    "RULE-005": ["AML.T0048", "AML.T0020"],
}


def load_atlas_data() -> Dict[str, dict]:
    """Loads the MITRE ATLAS JSON and returns a dict keyed by technique ID."""
    with open(ATLAS_DATA_PATH, "r") as f:
        data = json.load(f)
    return {technique["id"]: technique for technique in data["techniques"]}


def get_atlas_references(rule_id: str) -> List[ATLASReference]:
    """
    Returns a list of ATLASReference objects for the given rule ID.
    Returns an empty list if the rule has no ATLAS mapping.
    """
    atlas_data = load_atlas_data()
    technique_ids = RULE_TO_ATLAS.get(rule_id, [])

    references = []
    for technique_id in technique_ids:
        technique = atlas_data.get(technique_id)
        if technique:
            references.append(ATLASReference(
                id=technique["id"],
                name=technique["name"],
                tactic=technique["tactic"],
                url=technique["url"]
            ))
        else:
            logger.warning(f"ATLAS technique {technique_id} not found in data file")

    return references
