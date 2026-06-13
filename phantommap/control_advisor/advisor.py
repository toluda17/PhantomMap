"""
advisor.py

Maps each PhantomMap rule ID to a set of prioritised control
recommendations. The advisor annotates findings with concrete,
actionable controls after framework mapping is complete.

Controls are tiered by priority:
  immediate  — must be addressed before production deployment
  short_term — should be addressed within the next sprint or quarter
  long_term  — architectural or process improvements for the roadmap
"""

from typing import List, Dict
from phantommap.models.finding import Finding, Control
from phantommap.logger import get_logger

logger = get_logger(__name__)

# Control library -- keyed by control ID for deduplication.
# Each entry is a dict matching the Control dataclass fields.
CONTROL_LIBRARY: Dict[str, dict] = {
    "CTRL-001": {
        "title": "Input Validation and Sanitisation",
        "description": (
            "Validate and sanitise all external input before it reaches the LLM "
            "context window. Reject or escape inputs containing instruction-like "
            "patterns, delimiter sequences, or known injection payloads."
        ),
        "priority": "immediate"
    },
    "CTRL-002": {
        "title": "System Prompt Hardening",
        "description": (
            "Structure system prompts to explicitly define the LLM's role, "
            "permitted actions, and response boundaries. Use clear delimiters "
            "between system instructions and user-supplied content. Treat the "
            "instruction hierarchy as a security control, not just a UX choice."
        ),
        "priority": "immediate"
    },
    "CTRL-003": {
        "title": "Output Anomaly Detection",
        "description": (
            "Monitor LLM outputs for anomalous patterns before they reach "
            "downstream systems — unexpected data formats, exfiltration-like "
            "structures, or outputs that reference system prompt content. "
            "Flag or block anomalous responses for review."
        ),
        "priority": "short_term"
    },
    "CTRL-004": {
        "title": "Data Minimisation Before LLM Submission",
        "description": (
            "Audit what data is included in LLM prompts and strip anything "
            "not required for the specific task. PII, internal pricing, "
            "credentials, and policy details should never appear in prompts "
            "unless strictly necessary."
        ),
        "priority": "immediate"
    },
    "CTRL-005": {
        "title": "Provider Data Processing Agreement Review",
        "description": (
            "Review and document the LLM provider's data retention, logging, "
            "and training data policies. Ensure a data processing agreement "
            "is in place. Evaluate opt-out mechanisms for prompt logging "
            "and model training."
        ),
        "priority": "short_term"
    },
    "CTRL-006": {
        "title": "Prompt Confidentiality Controls",
        "description": (
            "Ensure submitted prompts — including system instructions and "
            "retrieved context — are treated as sensitive data in transit "
            "and at rest. Use TLS for all LLM API calls and audit access "
            "to prompt logs."
        ),
        "priority": "short_term"
    },
    "CTRL-007": {
        "title": "Least-Privilege Integration Credentials",
        "description": (
            "Apply least-privilege principles to all integration service "
            "accounts. The LLM agent should only have the minimum permissions "
            "required for its defined tasks — read-only where possible, "
            "scoped write access where not."
        ),
        "priority": "immediate"
    },
    "CTRL-008": {
        "title": "Human-in-the-Loop Review for Consequential Actions",
        "description": (
            "Require explicit human approval before the LLM agent executes "
            "irreversible or high-impact actions — writes, deletions, "
            "external communications. Implement a confirmation step that "
            "cannot be bypassed by prompt manipulation."
        ),
        "priority": "immediate"
    },
    "CTRL-009": {
        "title": "Action Scope Limiting",
        "description": (
            "Define and enforce strict boundaries on what actions the LLM "
            "agent is permitted to take. Use an allowlist of permitted "
            "operations rather than a blocklist. Reject any action request "
            "that falls outside the defined scope."
        ),
        "priority": "short_term"
    },
    "CTRL-010": {
        "title": "Output Sanitisation Before Downstream Use",
        "description": (
            "Treat all LLM output as untrusted. Apply context-appropriate "
            "sanitisation before rendering in a UI (XSS), writing to a "
            "database (SQLi), or passing to a shell (command injection). "
            "Never assume LLM output is safe because the prompt was safe."
        ),
        "priority": "immediate"
    },
    "CTRL-011": {
        "title": "Output Schema Validation",
        "description": (
            "Where LLM output is used programmatically, enforce a strict "
            "output schema. Validate structure, types, and value ranges "
            "before the output is consumed by downstream systems. Reject "
            "responses that don't conform."
        ),
        "priority": "short_term"
    },
    "CTRL-012": {
        "title": "AI Component Software Bill of Materials",
        "description": (
            "Maintain a software bill of materials (SBOM) covering all "
            "AI components — model providers, versions, plugins, datasets, "
            "and fine-tuning sources. Review the SBOM when components "
            "update and assess the security impact of changes."
        ),
        "priority": "long_term"
    },
    "CTRL-013": {
        "title": "Provider Security Monitoring",
        "description": (
            "Subscribe to security advisories from all third-party AI "
            "providers and integration vendors. Establish a process for "
            "assessing and responding to provider-side vulnerabilities, "
            "model updates, and policy changes."
        ),
        "priority": "short_term"
    },
    "CTRL-014": {
        "title": "Model Provenance Verification",
        "description": (
            "Verify the provenance and integrity of any third-party or "
            "fine-tuned models before deployment. Use checksums or signed "
            "artefacts where available. Document the model source and "
            "version in the SBOM."
        ),
        "priority": "long_term"
    },
}

# Maps rule IDs to the control IDs that apply.
RULE_TO_CONTROLS: Dict[str, List[str]] = {
    "RULE-001": ["CTRL-001", "CTRL-002", "CTRL-003"],
    "RULE-002": ["CTRL-004", "CTRL-005", "CTRL-006"],
    "RULE-003": ["CTRL-007", "CTRL-008", "CTRL-009"],
    "RULE-004": ["CTRL-010", "CTRL-011"],
    "RULE-005": ["CTRL-012", "CTRL-013", "CTRL-014"],
}


def advise_controls(findings: List[Finding]) -> List[Finding]:
    """
    Annotates each finding with its recommended controls.
    After controls are attached, recomputes the score -- controls
    present means the unmitigated bonus no longer applies.
    Returns the same list, mutated in place.
    """
    logger.info(f"Advising controls for {len(findings)} findings")

    for finding in findings:
        control_ids = RULE_TO_CONTROLS.get(finding.rule_id, [])
        finding.controls = [
            Control(
                id=ctrl_id,
                title=CONTROL_LIBRARY[ctrl_id]["title"],
                description=CONTROL_LIBRARY[ctrl_id]["description"],
                priority=CONTROL_LIBRARY[ctrl_id]["priority"]
            )
            for ctrl_id in control_ids
            if ctrl_id in CONTROL_LIBRARY
        ]

        # Recompute score now that controls are attached.
        # The unmitigated bonus (1.0) drops off if controls exist.
        finding.compute_score()

        logger.debug(
            f"{finding.id} | controls={[c.id for c in finding.controls]} "
            f"| final_score={finding.score}"
        )

    logger.info("Control advice complete")
    return findings
