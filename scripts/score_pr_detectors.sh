#!/usr/bin/env bash
# Score detectors changed by the current PR.
#
# Writes the JSON output to scoring-results.json and prints a markdown
# summary table to stdout suitable for posting as a PR comment. Used by
# the .github/workflows/detector-scoring.yml job.
#
# Usage:
#   scripts/score_pr_detectors.sh                   # vs origin/main
#   BASE_REF=upstream/main scripts/score_pr_detectors.sh
#
# Exit status mirrors score.py:
#   0 — all selected detectors scored cleanly
#   1 — at least one detector errored (subprocess crash, missing fixture)
#   2 — corpus load failure (treated as a hard CI failure)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

BASE_REF="${BASE_REF:-origin/main}"
RESULTS_FILE="${RESULTS_FILE:-scoring-results.json}"

if command -v uv >/dev/null 2>&1; then
  PYTHON_CMD=(uv run --group dev python)
else
  PYTHON_CMD=(python)
fi

# Run the scorer and capture both the JSON payload and the rendered
# markdown table. We split the two by relying on `--markdown` which
# appends a markdown block after a blank line.
set +e
SCORE_OUTPUT="$(
  "${PYTHON_CMD[@]}" \
    skills/detection-engineering/scoring/score.py \
    --changed-only \
    --base "$BASE_REF" \
    --markdown
)"
SCORE_STATUS=$?
set -e

# JSON payload runs from the first '{' to the last '}'. Anything after
# the closing brace is the markdown summary.
JSON_END_LINE="$(printf '%s\n' "$SCORE_OUTPUT" | grep -n '^}$' | tail -1 | cut -d: -f1)"

if [ -z "${JSON_END_LINE:-}" ]; then
  echo "score_pr_detectors: could not parse score output" >&2
  printf '%s\n' "$SCORE_OUTPUT" >&2
  exit 2
fi

JSON_PAYLOAD="$(printf '%s\n' "$SCORE_OUTPUT" | sed -n "1,${JSON_END_LINE}p")"
MARKDOWN_TABLE="$(printf '%s\n' "$SCORE_OUTPUT" | sed -n "$((JSON_END_LINE + 1)),\$p")"

printf '%s\n' "$JSON_PAYLOAD" > "$RESULTS_FILE"
echo "score_pr_detectors: wrote $RESULTS_FILE" >&2

cat <<HEADER
## Detector precision/recall (synthetic corpus)

This run scores detectors whose \`src/detect.py\` changed against
\`$BASE_REF\`. All entries in the corpus are synthetic — see
[\`skills/detection-engineering/golden/README.md\`](../skills/detection-engineering/golden/README.md)
for the honesty contract.

HEADER

if [ -z "${MARKDOWN_TABLE//[[:space:]]/}" ]; then
  echo "_No corpus entries matched the changed-only filter._"
else
  printf '%s\n' "$MARKDOWN_TABLE"
fi

exit $SCORE_STATUS
