# PhantomMap

I built PhantomMap to map attack surfaces in LLM-integrated and agentic applications. It cross-references identified risks against the OWASP Top 10 for LLMs and MITRE ATLAS, and generates structured threat reports with prioritised control recommendations.

I contribute to the [OWASP GenAI Security Project](https://owasp.org/www-project-top-10-for-large-language-model-applications/), so this isn't just a technical exercise — I wanted a tool that reflects how I actually think about AI security risk.

---

## What it does

You give PhantomMap a YAML description of an LLM-integrated application — its components, data flows, integrations, and trust boundaries. It runs the profile through a rule-based risk engine, annotates each finding with OWASP LLM Top 10 2025 and MITRE ATLAS 4.5 references, scores the findings, attaches prioritised control recommendations, and writes a full threat report in JSON and Markdown.

The output is the kind of structured risk assessment you'd hand to a security team doing an AI deployment review.

---

## Demo

I tested it against a RAG-based customer support chatbot with a CRM integration, no human-in-the-loop review, and an untrusted external LLM provider.

```bash
python3 -m phantommap.runner profiles/example_rag_app.yaml
```


11 findings across 14 attack surfaces. 2 CRITICAL, 8 HIGH, 1 MEDIUM. Highest score: 10.0 / 10.0.


---

## Architecture

```
Input (YAML profile)
        ↓
   Surface Mapper      ← extracts components, flows, integrations as attack surfaces
        ↓
   Risk Engine         ← applies 5 rule-based detections against each surface
        ↓
   Framework Mapper    ← annotates findings with OWASP LLM Top 10 + MITRE ATLAS
        ↓
   Control Advisor     ← attaches prioritised control recommendations
        ↓
   Report Generator    ← writes JSON + Markdown threat reports to output/
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full breakdown of each component.

---

## Risk rules

| Rule | Name | OWASP LLM | MITRE ATLAS |
|---|---|---|---|
| RULE-001 | Prompt Injection | LLM01:2025, LLM07:2025 | AML.T0051, AML.T0054, AML.T0043 |
| RULE-002 | Sensitive Data Exfiltration | LLM02:2025, LLM06:2025 | AML.T0037, AML.T0040, AML.T0044 |
| RULE-003 | Excessive Agency | LLM06:2025 | AML.T0047, AML.T0051 |
| RULE-004 | Insecure Output Handling | LLM05:2025 | AML.T0043, AML.T0047 |
| RULE-005 | Supply Chain Risk | LLM03:2025 | AML.T0048, AML.T0020 |

---

## Scoring

Each finding gets a composite score from 0.0 to 10.0:

- **Base score** from severity (CRITICAL = 9.0, HIGH = 7.0, MEDIUM = 5.0, LOW = 3.0)
- **+0.5** per OWASP reference (multi-framework validation adds weight)
- **+0.5** per ATLAS reference
- **+1.0** if no controls are defined (unmitigated risk)
- Capped at 10.0

---

## Frameworks

- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS v4.5](https://atlas.mitre.org/)

---

## Setup

```bash
git clone https://github.com/toluda17/PhantomMap.git
cd PhantomMap
pip3 install -r requirements.txt
python3 -m phantommap.runner profiles/example_rag_app.yaml
```

Reports are written to `output/` as `phantommap_<timestamp>.json` and `phantommap_<timestamp>.md`.

---

## Project structure

```
phantommap/
├── models/          # AppProfile and Finding dataclasses
├── surface_mapper/  # extracts attack surfaces from the profile
├── risk_engine/     # 5 rule-based detections
├── framework_mapper/# OWASP LLM + MITRE ATLAS annotation
├── control_advisor/ # prioritised control recommendations
└── report_generator/# JSON and Markdown output

data/                # OWASP LLM Top 10 and MITRE ATLAS reference JSON
profiles/            # YAML application profiles (input)
output/              # generated reports (gitignored)
```

---

## Writing a profile

Copy `profiles/example_rag_app.yaml` and describe your target application. The fields that drive detection:

- `human_in_the_loop: false` — triggers excessive agency findings
- `accepts_external_input: true` on a component — triggers prompt injection
- `carries_sensitive_data: true` + `crosses_trust_boundary: true` on a flow — triggers data exfiltration
- `trusted: false` on an integration — triggers supply chain risk
- `has_write_access: true` on an integration — triggers excessive agency
