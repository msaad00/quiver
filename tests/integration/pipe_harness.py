"""Shared helpers for ingest→detect golden pipe integration tests."""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILLS_ROOT = REPO_ROOT / "skills"
INGESTION_DIR = SKILLS_ROOT / "ingestion"
DETECTION_DIR = SKILLS_ROOT / "detection"
GOLDEN_DIR = SKILLS_ROOT / "detection-engineering" / "golden"


@dataclass(frozen=True)
class IngestDetectPipe:
    """One frozen raw→ingest→detect→findings pipe."""

    name: str
    ingest_skill: str
    detect_skill: str
    raw_fixture: str
    expected_fixture: str
    raw_json_document: bool = False
    expected_ocsf_count: int | None = None
    expected_finding_count: int | None = None


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"could not spec {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def run_ingest_detect_pipe(pipe: IngestDetectPipe) -> tuple[list[dict], list[dict]]:
    ingest = load_module(
        f"_pipe_ingest_{pipe.name}",
        INGESTION_DIR / pipe.ingest_skill / "src" / "ingest.py",
    )
    detect = load_module(
        f"_pipe_detect_{pipe.name}",
        DETECTION_DIR / pipe.detect_skill / "src" / "detect.py",
    )
    raw_path = GOLDEN_DIR / pipe.raw_fixture
    raw_text = raw_path.read_text(encoding="utf-8")
    raw_stream = [raw_text] if pipe.raw_json_document else raw_text.splitlines()
    ocsf_events = list(ingest.ingest(raw_stream))
    findings = list(detect.detect(ocsf_events))
    return ocsf_events, findings
