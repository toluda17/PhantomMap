"""
mapper.py

The surface mapper takes a parsed AppProfile and extracts attack surfaces --
specific points in the application that the risk engine should evaluate.

Each surface is a dict describing one potentially exploitable element:
a component, a data flow, or an integration. Surfaces are the unit of
analysis the risk rules operate against.
"""

from typing import List, Dict, Any
from phantommap.models.app_profile import AppProfile
from phantommap.logger import get_logger

logger = get_logger(__name__)


def extract_surfaces(profile: AppProfile) -> List[Dict[str, Any]]:
    """
    Extracts attack surfaces from an AppProfile.

    Iterates over components, data flows, and integrations, tagging each
    with properties relevant to risk analysis. Returns a flat list of
    surface dicts for the risk engine to evaluate.

    Each surface dict has at minimum:
        - surface_type: "component" | "data_flow" | "integration"
        - name: human-readable identifier
        - source_object: the original dataclass instance
        - properties: dict of risk-relevant flags
    """
    surfaces = []

    logger.info(f"Extracting surfaces from profile: {profile.name}")

    # ── Components ────────────────────────────────────────────────────────────
    for component in profile.components:
        surface = {
            "surface_type": "component",
            "name": component.name,
            "source_object": component,
            "properties": {
                "type": component.type,
                "accepts_external_input": component.accepts_external_input,
                "handles_pii": component.handles_pii,
                "description": component.description,
                # Profile-level context passed down to each surface
                "human_in_the_loop": profile.human_in_the_loop,
            }
        }
        surfaces.append(surface)
        logger.debug(f"  Component surface: {component.name}")

    # ── Data Flows ────────────────────────────────────────────────────────────
    for flow in profile.data_flows:
        surface = {
            "surface_type": "data_flow",
            "name": f"{flow.source} → {flow.destination}",
            "source_object": flow,
            "properties": {
                "source": flow.source,
                "destination": flow.destination,
                "carries_sensitive_data": flow.carries_sensitive_data,
                "crosses_trust_boundary": flow.crosses_trust_boundary,
                "description": flow.description,
                "human_in_the_loop": profile.human_in_the_loop,
            }
        }
        surfaces.append(surface)
        logger.debug(f"  Data flow surface: {surface['name']}")

    # ── Integrations ──────────────────────────────────────────────────────────
    for integration in profile.integrations:
        surface = {
            "surface_type": "integration",
            "name": integration.name,
            "source_object": integration,
            "properties": {
                "type": integration.type,
                "trusted": integration.trusted,
                "has_write_access": integration.has_write_access,
                "description": integration.description,
                "human_in_the_loop": profile.human_in_the_loop,
            }
        }
        surfaces.append(surface)
        logger.debug(f"  Integration surface: {integration.name}")

    logger.info(f"Extracted {len(surfaces)} surfaces total")
    return surfaces
