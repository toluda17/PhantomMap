"""
finding.py

The Finding dataclass is the core output unit of PhantomMap. Every risk
the engine identifies becomes a Finding -- the framework mapper annotates
it, the control advisor populates its recommendations, and the report
generator serialises it.

The score field is computed, not set manually. Base severity comes from
the rule that fired. The framework mapper adds weight if multiple
frameworks flag the same risk. Missing controls push it higher.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class Severity(str, Enum):
    """
    Severity levels for findings. I use a string enum so severity values
    serialise cleanly to JSON and Markdown without extra conversion.
    """
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# Base numeric scores by severity -- used as the starting point for
# composite scoring. Scale is 0-10.
SEVERITY_BASE_SCORES = {
    Severity.CRITICAL : 9.0,
    Severity.HIGH     : 7.0,
    Severity.MEDIUM   : 5.0,
    Severity.LOW      : 3.0,
    Severity.INFO     : 1.0,
}


@dataclass
class OWASPReference:
    """A reference to an OWASP LLM Top 10 entry."""
    id: str            # e.g. "LLM01:2025"
    name: str          # e.g. "Prompt Injection"
    url: str


@dataclass
class ATLASReference:
    """A reference to a MITRE ATLAS tactic or technique."""
    id: str            # e.g. "AML.T0051"
    name: str          # e.g. "LLM Prompt Injection"
    tactic: str        # e.g. "Initial Access"
    url: str


@dataclass
class Control:
    """A single recommended control for a finding."""
    id: str            # e.g. "CTRL-001"
    title: str
    description: str
    priority: str      # "immediate", "short_term", "long_term"


@dataclass
class Finding:
    """
    A single risk finding produced by PhantomMap.

    Fields are populated incrementally as the finding moves through the
    pipeline -- the risk rule sets the core fields, the framework mapper
    adds references, the control advisor adds recommendations, and the
    scorer computes the final score.
    """
    id: str                          # e.g. "FIND-001"
    title: str
    description: str
    severity: Severity
    affected_surface: str            # which component/flow triggered this
    rule_id: str                     # which rule fired

    # Populated by framework mapper
    owasp_references: List[OWASPReference] = field(default_factory=list)
    atlas_references: List[ATLASReference] = field(default_factory=list)

    # Populated by control advisor
    controls: List[Control] = field(default_factory=list)

    # Computed score (0.0 - 10.0)
    score: float = 0.0

    # Optional extra context from the rule
    notes: Optional[str] = None

    def compute_score(self) -> float:
        """
        Computes a composite risk score for this finding.

        Starts from the base severity score, then:
        - adds 0.5 for each OWASP reference (multi-framework validation)
        - adds 0.5 for each ATLAS reference
        - adds 1.0 if no controls are defined (unmitigated risk)
        Capped at 10.0.
        """
        base = SEVERITY_BASE_SCORES.get(self.severity, 5.0)
        bonus = (len(self.owasp_references) * 0.5) + \
                (len(self.atlas_references) * 0.5)
        unmitigated = 1.0 if not self.controls else 0.0
        self.score = min(round(base + bonus + unmitigated, 1), 10.0)
        return self.score
