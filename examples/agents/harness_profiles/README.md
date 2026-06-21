# LangGraph harness profiles

Profiles are operator-owned configuration for the example harness. They do not
store secrets, credentials, OAuth callbacks, passwords, or approval tokens.

Use a profile with:

```bash
DEMO_HARNESS_PROFILE=examples/agents/harness_profiles/readonly-soc.json \
python examples/agents/langgraph_security_graph.py
```

Generate a custom profile with:

```bash
python examples/agents/configure_langgraph_harness.py \
  --role dry-run-remediation \
  --profile-id acme-remediation-dryrun \
  --email security@example.com \
  --cloud-hint aws=AWS_PROFILE=prod-readonly \
  --output-profile artifacts/acme-remediation-dryrun.json \
  --output-env artifacts/acme-remediation-dryrun.env
```

The generated dotenv file points `CLOUD_SECURITY_HARNESS_PROFILE` and
`DEMO_HARNESS_PROFILE` at the profile. It intentionally omits `DEMO_APPROVE`;
approval still has to come from an explicit human approval context at runtime.

Profiles control:

- `allowed_skills`: operator-chosen skill surface; the example intersects it
  with the repo's known read/write skill set.
- `caller_context`: stable human or agent identity metadata for audit.
- `cloud_identity_hints`: commands or env hints the agent can surface to a
  human; credentials stay in the provider CLI/SDK chain.
- `llm`: provider/model metadata for bounded triage; model output can only
  rank, summarize, draft, or request human review.
- `approval_policy`: documentation of the HITL source; profiles never grant
  approval by themselves.

Included profiles:

| Profile | Use |
|---|---|
| `readonly-soc.json` | SOC replay and triage without remediation tools |
| `analyst-triage.json` | Optional external-model metadata for analyst drafting |
| `dry-run-remediation.json` | HITL-gated dry-run remediation planning |
