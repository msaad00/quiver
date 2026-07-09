"""Agent harness tests."""

from __future__ import annotations

import sys
from pathlib import Path

_AGENTS_DIR = Path(__file__).resolve().parents[2]
if str(_AGENTS_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTS_DIR))

import json
import os
import subprocess
import sys

from harness_shared import (
    EXAMPLES,
    SCHEMAS,
    schema_errors,
)


class TestOpenAICompatAdapter:
    """Live BYOM adapter: bounded request shape, tolerant parsing, safe failure."""

    @staticmethod
    def _adapters():
        sys.path.insert(0, str(EXAMPLES))
        try:
            import harness_adapters
        finally:
            sys.path.pop(0)
        return harness_adapters

    @staticmethod
    def _cards():
        return [{"finding_uid": "det-1", "title": "access key created", "severity": "high"}]

    def _response(self, content: str) -> bytes:
        return json.dumps({"choices": [{"message": {"content": content}}]}).encode("utf-8")

    def _fake_urlopen(self, monkeypatch, adapters, body: bytes, capture: dict):
        import contextlib
        import io

        @contextlib.contextmanager
        def fake_urlopen(request, timeout=None):
            capture["url"] = request.full_url
            capture["headers"] = dict(request.header_items())
            capture["body"] = json.loads(request.data.decode("utf-8"))
            capture["timeout"] = timeout
            yield io.BytesIO(body)

        monkeypatch.setattr(adapters.urllib.request, "urlopen", fake_urlopen)

    def test_sends_bounded_openai_request(self, monkeypatch):
        adapters = self._adapters()
        capture: dict = {}
        content = json.dumps(
            [
                {
                    "finding_uid": "det-1",
                    "priority": "high",
                    "recommended_action": "investigate",
                    "rationale": "new key on a build principal",
                }
            ]
        )
        self._fake_urlopen(monkeypatch, adapters, self._response(content), capture)

        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1/",
            model="gpt-4.1-mini",
            evidence_cards=self._cards(),
            api_key="test-key",
            timeout_seconds=999,
        )
        recommendations = adapter.recommendations()

        assert capture["url"] == "https://llm.example/v1/chat/completions"
        assert capture["headers"].get("Authorization") == "Bearer test-key"
        assert capture["body"]["model"] == "gpt-4.1-mini"
        assert capture["body"]["temperature"] == 0
        assert capture["timeout"] == 120  # clamped to the bounded maximum
        system_prompt = capture["body"]["messages"][0]["content"]
        assert "rank, summarize, and draft only" in system_prompt
        assert "never approve" in system_prompt
        assert recommendations == [
            {
                "finding_uid": "det-1",
                "priority": "high",
                "recommended_action": "investigate",
                "rationale": "new key on a build principal",
            }
        ]
        assert adapter.last_error is None

    def test_parses_fenced_json_and_recommendations_object(self, monkeypatch):
        adapters = self._adapters()
        payload = {
            "recommendations": [
                {
                    "finding_uid": "det-1",
                    "priority": "medium",
                    "recommended_action": "close",
                    "rationale": "benign automation",
                }
            ]
        }
        content = "```json\n" + json.dumps(payload) + "\n```"
        self._fake_urlopen(monkeypatch, adapters, self._response(content), {})

        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1",
            model="m",
            evidence_cards=self._cards(),
        )
        assert adapter.recommendations() == payload["recommendations"]

    def test_keyless_endpoint_sends_no_auth_header(self, monkeypatch):
        adapters = self._adapters()
        capture: dict = {}
        self._fake_urlopen(monkeypatch, adapters, self._response("[]"), capture)

        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="http://127.0.0.1:11434/v1",
            model="llama3",
            evidence_cards=self._cards(),
        )
        adapter.recommendations()
        assert "Authorization" not in capture["headers"]

    def test_network_failure_degrades_to_no_candidates(self, monkeypatch):
        adapters = self._adapters()

        def fail_urlopen(request, timeout=None):
            raise adapters.urllib.error.URLError("connection refused")

        monkeypatch.setattr(adapters.urllib.request, "urlopen", fail_urlopen)
        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1",
            model="m",
            evidence_cards=self._cards(),
        )
        assert adapter.recommendations() == []
        assert "URLError" in (adapter.last_error or "")

    def test_non_json_content_degrades_to_no_candidates(self, monkeypatch):
        adapters = self._adapters()
        self._fake_urlopen(monkeypatch, adapters, self._response("I think this looks fine."), {})
        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1",
            model="m",
            evidence_cards=self._cards(),
        )
        assert adapter.recommendations() == []
        assert adapter.last_error is not None

    def test_empty_evidence_skips_the_network_entirely(self, monkeypatch):
        adapters = self._adapters()

        def explode(request, timeout=None):  # pragma: no cover - must not run
            raise AssertionError("no network call expected without evidence")

        monkeypatch.setattr(adapters.urllib.request, "urlopen", explode)
        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1",
            model="m",
            evidence_cards=[],
        )
        assert adapter.recommendations() == []

    def test_selection_requires_external_mode_and_base_url(self, monkeypatch):
        adapters = self._adapters()

        offline = adapters.select_triage_adapter(
            harness_config={"mode": "deterministic_offline", "model": "m"},
            environ={"DEMO_OPENAI_BASE_URL": "https://llm.example/v1"},
            evidence_cards=self._cards(),
        )
        assert offline.adapter_id == "deterministic_fallback"

        no_url = adapters.select_triage_adapter(
            harness_config={"mode": "external_llm_optional", "model": "m"},
            environ={},
            evidence_cards=self._cards(),
        )
        assert no_url.adapter_id == "deterministic_fallback"

        live = adapters.select_triage_adapter(
            harness_config={"mode": "external_llm_optional", "model": "gpt-4.1-mini"},
            environ={
                "DEMO_OPENAI_BASE_URL": "https://llm.example/v1",
                "DEMO_OPENAI_API_KEY_ENV": "MY_KEY",
                "MY_KEY": "secret",
                "DEMO_OPENAI_TIMEOUT_SECONDS": "5",
            },
            evidence_cards=self._cards(),
        )
        assert live.adapter_id == "openai_compat_adapter"
        assert live.model == "gpt-4.1-mini"
        assert live.api_key == "secret"
        assert live.timeout_seconds == 5

    def test_fixture_adapter_still_beats_live_endpoint(self, tmp_path, monkeypatch):
        adapters = self._adapters()
        fixture = tmp_path / "fixture.json"
        fixture.write_text("[]", encoding="utf-8")
        selected = adapters.select_triage_adapter(
            harness_config={"mode": "external_llm_optional", "model": "m"},
            environ={
                "DEMO_LLM_ADAPTER_FIXTURE": str(fixture),
                "DEMO_OPENAI_BASE_URL": "https://llm.example/v1",
            },
            evidence_cards=self._cards(),
        )
        assert selected.adapter_id == "fixture_llm_adapter"

    def test_live_output_still_passes_the_schema_gate(self, monkeypatch):
        """A live adapter that emits forbidden keys is rejected downstream."""
        adapters = self._adapters()
        content = json.dumps(
            [
                {
                    "finding_uid": "det-1",
                    "priority": "high",
                    "recommended_action": "request_approval",
                    "rationale": "looks bad",
                    "approval": {"approved": True},
                }
            ]
        )
        self._fake_urlopen(monkeypatch, adapters, self._response(content), {})
        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1",
            model="m",
            evidence_cards=self._cards(),
        )
        candidate = adapter.recommendations()[0]
        fallback = {"finding_uid": "det-1", "output_hash": "abc"}
        accepted, validation = adapters.validate_adapter_recommendation(
            candidate=candidate,
            fallback=fallback,
            finding_uid="det-1",
            harness_config={"provider": "openai", "model": "m"},
            adapter_id=adapter.adapter_id,
        )
        assert validation["status"] == "rejected"
        assert validation["reason"].startswith("forbidden_output:approval")
        assert accepted == fallback


class TestModelQualityEval:
    """Model-quality mode scores adapter agreement against the golden dataset."""

    SCRIPT = EXAMPLES / "eval_langgraph_harness.py"

    def _run(self, tmp_path, env=None, extra_args=()):
        report_path = tmp_path / "model-quality.json"
        run_env = {key: value for key, value in os.environ.items() if not key.startswith("DEMO_")}
        run_env.update(env or {})
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--model-quality",
                "--check",
                "--output",
                str(report_path),
                *extra_args,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env=run_env,
        )
        report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
        return result, report

    def test_default_run_agrees_with_golden_dataset(self, tmp_path):
        result, report = self._run(tmp_path)
        assert result.returncode == 0, result.stderr
        assert report["event"] == "langgraph_model_quality_eval"
        assert report["cases_total"] == 8
        assert report["agreement_rate"] == 1.0
        assert report["adapter_accepted"] >= 1
        assert report["adapter_env"] == {
            "fixture": False,
            "langchain_fixture": False,
            "live_openai_compat": False,
        }

    def test_low_quality_adapter_fails_the_gate(self, tmp_path):
        import hashlib

        # Same uid derivation the harness uses for the golden CreateAccessKey
        # event, so the schema gate accepts this low-quality recommendation.
        golden_event = {
            "source": "cloudtrail",
            "event_name": "CreateAccessKey",
            "actor_uid": "AIDAEXAMPLE",
            "resource_uid": "arn:aws:iam::111122223333:user/build-bot",
        }
        encoded = json.dumps(golden_event, sort_keys=True, separators=(",", ":")).encode()
        finding_uid = f"det-evt-{hashlib.sha256(encoded).hexdigest()[:12]}"

        fixture = tmp_path / "bad-adapter.json"
        # Valid schema, wrong triage: the gate accepts it, agreement drops.
        fixture.write_text(
            json.dumps(
                [
                    {
                        "finding_uid": finding_uid,
                        "priority": "low",
                        "recommended_action": "close",
                        "rationale": "nothing to see here",
                    }
                ]
            ),
            encoding="utf-8",
        )
        result, report = self._run(
            tmp_path,
            env={
                "DEMO_LLM_ADAPTER_FIXTURE": str(fixture),
                "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
            },
        )
        assert result.returncode == 1
        assert report["adapter_env"]["fixture"] is True
        assert report["agreement_rate"] < 1.0


class TestLangGraphHarnessEvals:
    """Regression coverage for profile/triage eval tracking."""

    SCRIPT = EXAMPLES / "eval_langgraph_harness.py"
    DATASET = EXAMPLES / "evals" / "langgraph_triage_golden.json"
    SCHEMA = SCHEMAS / "eval_report.schema.json"

    def test_golden_eval_report_passes(self):
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT), "--check"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        schema = json.loads(self.SCHEMA.read_text(encoding="utf-8"))
        assert schema_errors(schema, report) == []
        assert report["event"] == "langgraph_agent_harness_eval"
        assert report["dataset_version"] == "langgraph-agent-harness-golden-v1"
        assert report["cases_total"] == 8
        assert report["passed"] == 8
        assert report["failed"] == 0
        assert report["pass_rate"] == 1.0
        assert {case["case_id"] for case in report["results"]} == {
            "readonly_soc_blocks_remediation",
            "analyst_triage_records_model_metadata",
            "remediation_profile_does_not_approve_itself",
            "approved_dry_run_records_integrity_idempotency",
            "retryable_api_error_reuses_idempotency_key",
            "terminal_api_error_escalates_to_human_queue",
            "llm_adapter_accepts_bounded_triage",
            "llm_adapter_rejects_forbidden_security_facts",
        }

    def test_golden_dataset_is_valid_json(self):
        payload = json.loads(self.DATASET.read_text(encoding="utf-8"))
        assert payload["dataset_version"] == "langgraph-agent-harness-golden-v1"
        assert len(payload["cases"]) == 8

    def test_eval_report_can_be_written_and_appended(self, tmp_path):
        report_path = tmp_path / "langgraph-harness-eval.json"
        history_path = tmp_path / "langgraph-harness-eval-history.jsonl"
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--check",
                "--output",
                str(report_path),
                "--append-jsonl",
                str(history_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        stdout_report = json.loads(result.stdout)
        file_report = json.loads(report_path.read_text(encoding="utf-8"))
        history_rows = [
            json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines()
        ]
        assert file_report == stdout_report
        schema = json.loads(self.SCHEMA.read_text(encoding="utf-8"))
        assert schema_errors(schema, stdout_report) == []
        assert len(history_rows) == 1
        assert schema_errors(schema, history_rows[0]) == []
        assert history_rows[0]["event"] == "langgraph_agent_harness_eval"
        assert history_rows[0]["dataset_hash"] == stdout_report["dataset_hash"]
        assert history_rows[0]["pass_rate"] == 1.0
        assert history_rows[0]["report_hash"]
        assert history_rows[0]["recorded_at"].endswith("Z")
