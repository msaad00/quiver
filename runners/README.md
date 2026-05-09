# Runners

Runners are the persistent edge components around the stateless skills.

They own:
- source subscriptions and queue triggers
- checkpointing and replay position
- dedupe tables or sink merge semantics
- retry / DLQ behavior
- sink writes and alert fan-out

They do **not** change the skill contract. The same `SKILL.md + src/ + tests/`
bundle should still run unchanged from the CLI, CI, MCP, or a persistent loop.

Read next:

- [DEPLOYMENT_VERIFICATION.md](DEPLOYMENT_VERIFICATION.md)
- [../docs/DATA_HANDLING.md](../docs/DATA_HANDLING.md)

## Shipped reference runners

- [`aws-s3-sqs-detect`](aws-s3-sqs-detect/): S3 object create trigger -> ingest
  Lambda -> SQS detect queue -> detect Lambda -> DynamoDB dedupe -> SNS publish
- [`gcp-gcs-pubsub-detect`](gcp-gcs-pubsub-detect/): GCS finalize trigger ->
  ingest Cloud Function -> Pub/Sub detect topic -> detect Cloud Function ->
  Firestore dedupe -> findings topic
- [`azure-blob-eventgrid-detect`](azure-blob-eventgrid-detect/): Blob create ->
  Event Grid -> ingest queue -> ingest handler -> detect queue -> detect
  handler -> Table Storage dedupe -> Service Bus topic
- [`webhook-receiver`](webhook-receiver/): vendor-neutral HTTP receiver →
  any-source POST → shipped ingest skill → fan-out to S3 / Snowflake /
  ClickHouse sinks. Default-deny routing, HMAC + bearer auth, single-process
  FastAPI app deployable on App Runner / Cloud Run / Container Apps / Kubernetes.

This is a reference template, not a multi-tenant managed service. Operators still
own packaging, deployment, sink wiring, IAM review, and environment-specific
controls.

## Live Deployment Status

All three runners are shipped and CI-validated.

The repo does not yet claim a captured real-cloud deploy-and-first-event proof
for all three templates. That remaining work is tracked in
[`#198`](https://github.com/msaad00/cloud-ai-security-skills/issues/198) and
summarized in [DEPLOYMENT_VERIFICATION.md](DEPLOYMENT_VERIFICATION.md).

What is now committed:

- exact first-event walkthrough skeletons in each runner README
- the deploy/apply inputs that need to be bound
- the evidence operators should capture on the first successful run

What is still not claimed:

- a checked-in record that those walkthroughs were executed in AWS, GCP, and
  Azure against real deployed resources
