"""
rule_base.py

Abstract base class for all PhantomMap risk rules. Every rule inherits
from RuleBase and implements evaluate(). The engine calls evaluate() on
each surface without knowing anything about the rule's internal logic.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from phantommap.models.finding import Finding, Severity
from phantommap.logger import get_logger


class RuleBase(ABC):
    """
    Base class for all risk rules.

    Subclasses must define RULE_ID, NAME, and BASE_SEVERITY as class
    attributes, and implement the evaluate() method.
    """

    RULE_ID: str = ""
    NAME: str = ""
    BASE_SEVERITY: Severity = Severity.MEDIUM

    def __init__(self):
        self.logger = get_logger(f"rule.{self.RULE_ID}")

    @abstractmethod
    def evaluate(self, surface: Dict[str, Any]) -> Optional[Finding]:
        """
        Evaluates a single surface against this rule.

        Returns a Finding if the rule fires, or None if it doesn't.
        The finding is not yet scored or framework-annotated at this
        stage -- that happens in later pipeline layers.
        """
        pass

    def _make_finding(
        self,
        finding_id: str,
        title: str,
        description: str,
        affected_surface: str,
        severity: Optional[Severity] = None,
        notes: Optional[str] = None
    ) -> Finding:
        """
        Helper that constructs a Finding with this rule's metadata.
        Subclasses call this rather than instantiating Finding directly.
        """
        return Finding(
            id=finding_id,
            title=title,
            description=description,
            severity=severity or self.BASE_SEVERITY,
            affected_surface=affected_surface,
            rule_id=self.RULE_ID,
            notes=notes
        )
