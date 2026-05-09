# Workflows

Reference workflows that compose atomic skills into runnable security
operations. Each workflow is a markdown spec — the composition logic is
operator-owned, so the spec works equally well as a SOAR playbook, a
Step Function, a LangGraph graph, or a manual run-book.

The format is documented in [`../../docs/SKILL_COMPOSITION.md`](../../docs/SKILL_COMPOSITION.md).
The matching MCP allowlists are in [`../../presets/`](../../presets/).

## Shipped reference workflows

| Workflow | Trigger | Atoms | Preset |
|---|---|---|---|
| [`incident-response-okta-mfa-fatigue.md`](incident-response-okta-mfa-fatigue.md) | OCSF Detection Finding 2004 from `detect-okta-mfa-fatigue` | `detect-okta-mfa-fatigue` → `discover-control-evidence` → `remediate-okta-session-kill` | [`preset-incident-response.json`](../../presets/preset-incident-response.json) |

## Writing a new workflow

1. Pick the trigger first. If you can't cite an OCSF class / technique /
   feature name, the workflow probably needs a new atomic detector before
   it needs a workflow doc.
2. Define the smallest preset that covers the steps. Never reuse
   `preset-cspm-readonly.json` for a remediation chain — keep blast radius
   visible.
3. Author the markdown using the worked example as a template.
4. Add a row to the table above so the workflow is discoverable.

See the **Authoring checklist** at the bottom of
[`../../docs/SKILL_COMPOSITION.md`](../../docs/SKILL_COMPOSITION.md) for the
full bar each workflow must clear.
