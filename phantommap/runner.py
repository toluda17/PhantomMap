"""
runner.py

PhantomMap pipeline orchestrator. Accepts a path to an application
profile YAML file, runs the full analysis pipeline, and writes both
JSON and Markdown reports to the output directory.

Usage:
    python3 -m phantommap.runner profiles/example_rag_app.yaml
"""

import sys
import yaml
from pathlib import Path

from phantommap.models.app_profile import AppProfile, Component, DataFlow, Integration
from phantommap.surface_mapper import extract_surfaces
from phantommap.risk_engine import run_rules
from phantommap.framework_mapper import annotate_findings
from phantommap.control_advisor import advise_controls
from phantommap.report_generator import generate_json_report, generate_markdown_report
from phantommap.logger import get_logger

logger = get_logger(__name__)


def load_profile(profile_path: Path) -> AppProfile:
    """Parses a YAML profile file into an AppProfile dataclass."""
    with open(profile_path, "r") as f:
        data = yaml.safe_load(f)

    return AppProfile(
        name=data["name"],
        description=data["description"],
        version=data["version"],
        human_in_the_loop=data.get("human_in_the_loop", True),
        notes=data.get("notes"),
        components=[Component(**c) for c in data.get("components", [])],
        data_flows=[DataFlow(**f) for f in data.get("data_flows", [])],
        integrations=[Integration(**i) for i in data.get("integrations", [])],
    )


def run(profile_path: Path) -> None:
    """
    Runs the full PhantomMap pipeline against a profile and writes reports.

    Pipeline stages:
        1. Load profile      — parse YAML into AppProfile
        2. Map surfaces      — extract attack surfaces from profile
        3. Run rules         — identify risks against each surface
        4. Annotate          — cross-reference OWASP LLM Top 10 + MITRE ATLAS
        5. Advise controls   — attach prioritised control recommendations
        6. Generate reports  — write JSON and Markdown to output/
    """
    logger.info(f"PhantomMap starting — profile: {profile_path}")
    logger.info("=" * 60)

    # Stage 1 — Load profile
    logger.info("Stage 1/6 — Loading application profile")
    profile = load_profile(profile_path)
    logger.info(f"Loaded profile: {profile.name} (v{profile.version})")

    # Stage 2 — Map surfaces
    logger.info("Stage 2/6 — Mapping attack surfaces")
    surfaces = extract_surfaces(profile)

    # Stage 3 — Run rules
    logger.info("Stage 3/6 — Running risk rules")
    findings = run_rules(surfaces)

    # Stage 4 — Annotate with framework references
    logger.info("Stage 4/6 — Annotating with framework references")
    findings = annotate_findings(findings)

    # Stage 5 — Advise controls
    logger.info("Stage 5/6 — Advising controls")
    findings = advise_controls(findings)

    # Stage 6 — Generate reports
    logger.info("Stage 6/6 — Generating reports")
    json_path = generate_json_report(profile, findings)
    md_path = generate_markdown_report(profile, findings)

    logger.info("=" * 60)
    logger.info(f"PhantomMap complete — {len(findings)} findings")
    logger.info(f"JSON report : {json_path}")
    logger.info(f"MD report   : {md_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 -m phantommap.runner <profile.yaml>")
        sys.exit(1)

    profile_path = Path(sys.argv[1])

    if not profile_path.exists():
        print(f"Error: profile not found at {profile_path}")
        sys.exit(1)

    run(profile_path)
