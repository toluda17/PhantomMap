# PhantomMap — Architecture

PhantomMap is a static analysis tool for LLM-integrated applications. It does not
interact with live systems — it reasons against a structured description of an
application and produces a deterministic, auditable threat report.

---

## Pipeline overview

    profiles/example_rag_app.yaml
                down
          [ runner.py ]
                down
       [ surface_mapper ]    ->  14 surfaces (components, flows, integrations)
                down
       [ risk_engine ]       ->  11 raw findings
                down
       [ framework_mapper ]  ->  11 annotated findings (OWASP + ATLAS refs, scores)
                down
       [ control_advisor ]   ->  11 findings with controls, final scores
                down
       [ report_generator ]  ->  phantommap_timestamp.json + .md

Each stage is a pure function — given the same input it always produces
the same output. This makes the pipeline deterministic and testable.

---

## Components

### models/

Defines the two core data shapes the pipeline passes around:

- AppProfile — the parsed input. Contains Component, DataFlow, and Integration
  dataclasses describing the target application structure, trust boundaries,
  and external dependencies.

- Finding — the core output unit. Produced by the risk engine, annotated by the
  framework mapper and control advisor, serialised by the report generator.
  Carries severity, score, OWASP references, ATLAS references, and controls.

Defining data shapes before logic is a deliberate design choice — every module
has a typed contract to code against rather than passing raw dicts.

### surface_mapper/

Iterates over the AppProfile and extracts a flat list of attack surfaces — one
per component, data flow, and integration. Each surface carries the properties
relevant to risk analysis: does this accept external input? does this flow cross
a trust boundary?

The surface mapper separates the concern of what the application is from what
can be attacked. The risk engine never parses YAML — it reasons against surfaces.

### risk_engine/

Applies five rule classes against every surface. Each rule inherits from
RuleBase, which enforces the contract: declare RULE_ID, NAME, and BASE_SEVERITY,
implement evaluate(surface) -> Optional[Finding].

This is the Strategy pattern — adding a new rule is adding a new file. The
engine does not need to know anything about a rule internal logic.

Rule            | Fires when
----------------|------------------------------------------------------------
RULE-001        | Component accepts external input, or flow crosses trust boundary
RULE-002        | Sensitive data crosses trust boundary to untrusted integration
RULE-003        | Integration has write access and no human-in-the-loop
RULE-004        | LLM output flows to writable system without human review
RULE-005        | Integration is not trusted

### framework_mapper/

Annotates each finding with OWASP LLM Top 10 and MITRE ATLAS references loaded
from data/. Mapping is defined in two lookup tables — RULE_TO_OWASP and
RULE_TO_ATLAS — keyed by rule ID.

Framework annotation is deliberately separate from risk detection. Rules know
how to spot problems; the mapper knows which frameworks categorise them. Updating
framework mappings when OWASP releases a new version does not touch rule logic.

Composite scoring runs here, after annotation, because the score accounts for
how many frameworks flag a finding — that information only exists post-annotation.

### control_advisor/

Maps each rule ID to a set of Control objects from a 14-entry control library.
Controls are tiered by priority: immediate, short_term, long_term.

After controls are attached, scores are recomputed — the unmitigated bonus
(+1.0) drops off when controls exist, reflecting that the risk is now addressed.

### report_generator/

Serialises the final findings list to two formats:

- JSON — machine-readable, suitable for SIEM ingestion or downstream tooling
- Markdown — human-readable threat report with executive summary, severity
  breakdown, per-finding detail, OWASP/ATLAS links, and control recommendations

Both are generated from the same data model so they are always in sync.

---

## Design principles

Separation of concerns — each module has one job. The risk engine detects,
the framework mapper annotates, the control advisor recommends, the report
generator serialises. None of these layers knows about the others implementation.

Determinism — the same profile always produces the same findings. No randomness,
no external API calls at analysis time. This makes reports reproducible and auditable.

Minimal dependencies — only pyyaml and python-dotenv. Security tools with
sprawling dependencies are themselves a supply chain risk.

Typed contracts — dataclasses enforce the shape of data passed between layers.
No raw dict guessing; every module knows exactly what it is receiving.
