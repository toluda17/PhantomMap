# PhantomMap — Architecture

PhantomMap is a static analysis tool — it doesn't interact with live systems. I give it a structured description of an LLM-integrated application and it produces a deterministic, auditable threat report every time.

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

Each stage is a pure function — same input always produces the same output. That makes the pipeline deterministic and easy to reason about.

---

## Components

### models/

I defined the data shapes before writing any logic. Everything in the pipeline either produces or consumes one of two objects:

- AppProfile — the parsed input. Contains Component, DataFlow, and Integration
  dataclasses describing the target application, its trust boundaries, and
  external dependencies.

- Finding — the core output unit. The risk engine creates it, the framework
  mapper annotates it, the control advisor populates it, and the report
  generator serialises it. Carries severity, score, OWASP references, ATLAS
  references, and controls.

Doing it this way means every module has a typed contract to code against rather than passing raw dicts around and guessing what keys exist.

### surface_mapper/

Takes the AppProfile and pulls out a flat list of attack surfaces — one per component, data flow, and integration. Each surface carries the properties that matter for risk analysis: does this accept external input? does this flow cross a trust boundary?

I kept this separate from the risk engine deliberately. The engine never touches YAML — it just reasons against surfaces. If I wanted to support a different input format later, I'd only need to change the mapper.

### risk_engine/

Applies five rule classes against every surface. Each rule inherits from RuleBase, which enforces a simple contract: declare RULE_ID, NAME, and BASE_SEVERITY, implement evaluate(surface) -> Optional[Finding].

This is the Strategy pattern — adding a new rule means adding a new file, nothing else changes. The engine doesn't know or care what any rule's internal logic looks like.

Rule            | Fires when
----------------|------------------------------------------------------------
RULE-001        | Component accepts external input, or flow crosses trust boundary
RULE-002        | Sensitive data crosses trust boundary to untrusted integration
RULE-003        | Integration has write access and no human-in-the-loop
RULE-004        | LLM output flows to writable system without human review
RULE-005        | Integration is not trusted

### framework_mapper/

Annotates each finding with OWASP LLM Top 10 and MITRE ATLAS references, loaded from data/. The mapping lives in two lookup tables — RULE_TO_OWASP and RULE_TO_ATLAS — keyed by rule ID.

I kept framework annotation separate from risk detection on purpose. The rules know how to spot problems; the mapper knows which frameworks categorise them. When OWASP updates the LLM Top 10, I update the mapper and the data file — rule logic stays untouched.

Scoring also runs here rather than in the risk engine, because the composite score accounts for how many frameworks flag a finding — that information only exists after annotation.

### control_advisor/

Maps each rule ID to a set of Control objects from a 14-entry control library. Controls are tiered by priority: immediate, short_term, long_term.

After controls are attached, scores get recomputed — the unmitigated bonus (+1.0) drops off, since the risk now has remediation guidance attached.

### report_generator/

Serialises the final findings list to two formats:

- JSON — machine-readable, suitable for SIEM ingestion or downstream tooling
- Markdown — human-readable threat report with executive summary, severity
  breakdown, per-finding detail, OWASP/ATLAS links, and control recommendations

Both come from the same data model so they're always in sync.

---

## Design principles

**Separation of concerns** — each module has one job. The risk engine detects, the framework mapper annotates, the control advisor recommends, the report generator serialises. None of these layers knows about the others implementation.

**Determinism** — same profile, same findings, every time. No randomness, no external API calls during analysis. Reports are reproducible and auditable.

**Minimal dependencies** — just pyyaml and python-dotenv. Security tools with sprawling dependencies are themselves a supply chain risk.

**Typed contracts** — dataclasses enforce the shape of data passed between layers. No raw dict guessing anywhere in the pipeline.
