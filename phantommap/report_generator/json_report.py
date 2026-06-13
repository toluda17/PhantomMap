"""
json_report.py

Serialises PhantomMap findings to a structured JSON report file.
The JSON output is machine-readable and suitable for ingestion by
SIEMs, ticketing systems, or downstream tooling.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from phantommap.models.finding import Finding
from phantommap.models.app_profile import AppProfile
from phantommap.config import OUTPUT_DIR, REPORT_TOOL_NAME, REPORT_TOOL_VERSION
from phantommap.config import OWASP_LLM_VERSION, MITRE_ATLAS_VERSION
from phantommap.logger import get_logger

logger = get_logger(__name__)


def _serialise_finding(finding: Finding) -> dict:
    """Converts a Finding dataclass to a JSON-serialisable dict."""
    return {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "score": finding.score,
        "affected_surface": finding.affected_surface,
        "rule_id": finding.rule_id,
        "notes": finding.notes,
        "owasp_references": [
            {"id": r.id, "name": r.name, "url": r.url}
            for r in finding.owasp_references
        ],
        "atlas_references": [
            {"id": r.id, "name": r.name, "tactic": r.tactic, "url": r.url}
            for r in finding.atlas_references
        ],
        "controls": [
            {"id": c.id, "title": c.title, "description": c.description, "priority": c.priority}
            for c in finding.controls
        ],
    }


def generate_json_report(profile: AppProfile, findings: List[Finding]) -> Path:
    """
    Generates a JSON threat report and writes it to the output directory.
    Returns the path to the written file.
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"phantommap_{timestamp}.json"
    output_path = OUTPUT_DIR / filename

    severity_counts = {}
    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    report = {
        "tool": REPORT_TOOL_NAME,
        "version": REPORT_TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "frameworks": {
            "owasp_llm_top10": OWASP_LLM_VERSION,
            "mitre_atlas": MITRE_ATLAS_VERSION,
        },
        "application": {
            "name": profile.name,
            "description": profile.description,
            "version": profile.version,
            "human_in_the_loop": profile.human_in_the_loop,
        },
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "highest_score": max((f.score for f in findings), default=0.0),
        },
        "findings": [_serialise_finding(f) for f in findings],
    }

    with open(output_path, "w") as fp:
        json.dump(report, fp, indent=2)

    logger.info(f"JSON report written to {output_path}")
    return output_path
