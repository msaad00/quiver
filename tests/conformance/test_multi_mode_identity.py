"""Conformance tests for identical skill output across execution modes.

The repo contract says a shipped skill bundle behaves the same whether it is
invoked directly from the CLI, from CI as a subprocess, or through the MCP
wrapper. These tests pin that claim to real bytes for representative skills in
the ingest, detect, and evaluate layers.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SRC = REPO_ROOT / "mcp-server" / "src"
if str(MCP_SRC) not in sys.path:
    sys.path.insert(0, str(MCP_SRC))

from tool_registry import build_command, tool_map  # noqa: E402

SERVER_PATH = REPO_ROOT / "mcp-server" / "src" / "server.py"
GOLDEN_DIR = REPO_ROOT / "skills" / "detection-engineering" / "golden"


@dataclass(frozen=True)
class SkillConformanceCase:
    name: str
    args: tuple[str, ...] = ()
    input_text: str = ""
    output_format: str | None = None
    expected_exit_code: int = 0
    moto_fixture: str | None = None


@dataclass(frozen=True)
class ModeResult:
    stdout: str
    stderr: str
    exit_code: int

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.stdout.encode("utf-8")).hexdigest()


def _send_message(proc: subprocess.Popen[bytes], payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    proc.stdin.write(f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8"))
    proc.stdin.write(body)
    proc.stdin.flush()


def _read_message(proc: subprocess.Popen[bytes]) -> dict:
    headers: dict[str, str] = {}
    while True:
        line = proc.stdout.readline()
        assert line, proc.stderr.read().decode("utf-8")
        if line in (b"\r\n", b"\n"):
            break
        name, value = line.decode("utf-8").split(":", 1)
        headers[name.strip().lower()] = value.strip()
    length = int(headers["content-length"])
    return json.loads(proc.stdout.read(length).decode("utf-8"))


def _initialize(proc: subprocess.Popen[bytes]) -> None:
    _send_message(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    response = _read_message(proc)
    assert response["result"]["serverInfo"]["name"] == "cloud-ai-security-skills"
    _send_message(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})


def _subprocess_env(
    sitecustomize_dir: Path,
    *,
    moto_fixture: str | None = None,
) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{sitecustomize_dir}{os.pathsep}{existing_pythonpath}"
        if existing_pythonpath
        else str(sitecustomize_dir)
    )
    if moto_fixture:
        env["CLOUD_SECURITY_CONFORMANCE_MOTO_FIXTURE"] = moto_fixture
    else:
        env.pop("CLOUD_SECURITY_CONFORMANCE_MOTO_FIXTURE", None)
    return env


def _run_cli(case: SkillConformanceCase, env: dict[str, str]) -> ModeResult:
    spec = tool_map()[case.name]
    assert spec.entrypoint is not None, case.name
    command = [sys.executable, str(spec.entrypoint), *case.args]
    if case.output_format:
        command.extend(["--output-format", case.output_format])
    completed = subprocess.run(
        command,
        input=case.input_text,
        text=True,
        capture_output=True,
        cwd=REPO_ROOT,
        env=env,
        check=False,
    )
    return ModeResult(
        stdout=completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
    )


def _run_ci_subprocess(case: SkillConformanceCase, env: dict[str, str]) -> ModeResult:
    spec = tool_map()[case.name]
    command = build_command(spec, list(case.args), output_format=case.output_format)
    completed = subprocess.run(
        command,
        input=case.input_text,
        text=True,
        capture_output=True,
        cwd=REPO_ROOT,
        env=env,
        check=False,
    )
    return ModeResult(
        stdout=completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
    )


def _run_mcp(case: SkillConformanceCase, env: dict[str, str]) -> ModeResult:
    proc = subprocess.Popen(
        [sys.executable, str(SERVER_PATH)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=REPO_ROOT,
        env=env,
    )
    try:
        _initialize(proc)
        arguments: dict[str, object] = {"args": list(case.args), "input": case.input_text}
        if case.output_format:
            arguments["output_format"] = case.output_format
        _send_message(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": case.name, "arguments": arguments},
            },
        )
        response = _read_message(proc)
        result = response["result"]
        structured = result["structuredContent"]
        return ModeResult(
            stdout=structured["stdout"],
            stderr=structured["stderr"],
            exit_code=structured["exit_code"],
        )
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def conformance_sitecustomize_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("conformance-sitecustomize")
    (root / "sitecustomize.py").write_text(
        """\
import os

_fixture = os.environ.get("CLOUD_SECURITY_CONFORMANCE_MOTO_FIXTURE", "").strip()

if _fixture:
    from moto import mock_aws
    import boto3

    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

    _mock = mock_aws()
    _mock.start()

    if _fixture == "aws-cis-storage":
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="conformance-open-bucket")
""",
        encoding="utf-8",
    )
    return root


CASES = (
    SkillConformanceCase(
        name="ingest-cloudtrail-ocsf",
        input_text=(GOLDEN_DIR / "cloudtrail_raw_sample.jsonl").read_text(),
        output_format="ocsf",
    ),
    SkillConformanceCase(
        name="detect-lateral-movement",
        input_text=(GOLDEN_DIR / "lateral_movement_input.ocsf.jsonl").read_text(),
        output_format="ocsf",
    ),
    SkillConformanceCase(
        name="cspm-aws-cis-benchmark",
        args=("--region", "us-east-1", "--section", "storage", "--output", "json"),
        output_format="native",
        expected_exit_code=1,
        moto_fixture="aws-cis-storage",
    ),
)


class TestMultiModeIdentity:
    @pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
    def test_cli_ci_and_mcp_stdout_hashes_match(
        self,
        case: SkillConformanceCase,
        conformance_sitecustomize_dir: Path,
    ) -> None:
        env = _subprocess_env(
            conformance_sitecustomize_dir,
            moto_fixture=case.moto_fixture,
        )

        cli = _run_cli(case, env)
        ci = _run_ci_subprocess(case, env)
        mcp = _run_mcp(case, env)

        assert cli.stdout, f"{case.name}: CLI stdout was empty"
        assert ci.stdout, f"{case.name}: CI subprocess stdout was empty"
        assert mcp.stdout, f"{case.name}: MCP stdout was empty"

        assert cli.exit_code == ci.exit_code == mcp.exit_code == case.expected_exit_code, (
            f"{case.name}: mode exit-code drift\n"
            f"  cli={cli.exit_code} ci={ci.exit_code} mcp={mcp.exit_code}"
        )

        assert cli.sha256 == ci.sha256 == mcp.sha256, (
            f"{case.name}: stdout drift across runtime surfaces\n"
            f"  cli={cli.sha256}\n"
            f"  ci={ci.sha256}\n"
            f"  mcp={mcp.sha256}"
        )
