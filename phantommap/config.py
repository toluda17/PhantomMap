"""
config.py

Central configuration for PhantomMap. Paths, constants, and framework
version metadata all live here. Nothing in the pipeline hardcodes these
values -- they import from this module instead.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Paths ─────────────────────────────────────────────────────────────────────

# Root of the project (two levels up from this file: phantommap/ -> root)
ROOT_DIR    = Path(__file__).resolve().parent.parent

DATA_DIR    = ROOT_DIR / "data"
PROFILES_DIR = ROOT_DIR / "profiles"
OUTPUT_DIR  = ROOT_DIR / "output"

OWASP_DATA_PATH  = DATA_DIR / "owasp_llm_top10.json"
ATLAS_DATA_PATH  = DATA_DIR / "mitre_atlas.json"

# ── Logging ───────────────────────────────────────────────────────────────────

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# ── Framework versions ────────────────────────────────────────────────────────

# Update these if the underlying framework data files are refreshed.
OWASP_LLM_VERSION  = "2025"
MITRE_ATLAS_VERSION = "4.5"

# ── Scoring ───────────────────────────────────────────────────────────────────

# Score thresholds used in report summaries.
SCORE_CRITICAL_THRESHOLD = 8.5
SCORE_HIGH_THRESHOLD     = 6.5
SCORE_MEDIUM_THRESHOLD   = 4.5

# ── Report ────────────────────────────────────────────────────────────────────

REPORT_TOOL_NAME    = "PhantomMap"
REPORT_TOOL_VERSION = "0.1.0"
