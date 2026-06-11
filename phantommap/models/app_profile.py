"""
app_profile.py

Dataclasses that represent an application being analysed by PhantomMap.
I parse a YAML profile into these structures before passing anything to the
risk engine -- everything downstream works with typed objects, not raw dicts.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DataFlow:
    """
    A single data flow between two components in the application.

    Flows are directional -- source sends data to destination. The
    'carries_sensitive_data' flag is set by the profile author and
    influences risk scoring downstream.
    """
    source: str
    destination: str
    description: str
    carries_sensitive_data: bool = False
    crosses_trust_boundary: bool = False


@dataclass
class Integration:
    """
    An external service or system the application integrates with.

    Integrations are a key attack surface in LLM apps -- third-party
    model providers, vector databases, tool APIs. The 'trusted' flag
    reflects whether the integration is under the organisation's control.
    """
    name: str
    type: str          # e.g. "llm_provider", "vector_db", "crm", "email"
    description: str
    trusted: bool = True
    has_write_access: bool = False


@dataclass
class Component:
    """
    A logical component of the application -- a service, interface, or
    data store. Components are the nodes; DataFlows are the edges.
    """
    name: str
    type: str          # e.g. "user_interface", "llm_api", "vector_db", "backend"
    description: str
    accepts_external_input: bool = False
    handles_pii: bool = False


@dataclass
class AppProfile:
    """
    The full application profile parsed from a YAML input file.

    This is the root object I hand to the surface mapper. It contains
    everything PhantomMap knows about the target application.
    """
    name: str
    description: str
    version: str
    components: List[Component] = field(default_factory=list)
    data_flows: List[DataFlow] = field(default_factory=list)
    integrations: List[Integration] = field(default_factory=list)
    human_in_the_loop: bool = True
    notes: Optional[str] = None
