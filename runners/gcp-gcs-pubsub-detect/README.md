# gcp-gcs-pubsub-detect

Reference persistent runner template for continuous ingest -> detect pipelines
on GCP.

## What it does

```text
GCS object finalized
  -> ingest Cloud Function
  -> Pub/Sub detect topic
  -> detect Cloud Function
  -> Firestore dedupe
  -> Pub/Sub findings topic
```

The runner keeps state and side effects at the edges:
- Cloud Storage is the raw object source
- Pub/Sub provides durable decoupling and downstream fan-out
- Firestore stores replay-safe dedupe keys
- the skills remain unchanged and stateless

## When to use it

- You want a repo-owned GCP pattern that mirrors the shipped AWS runner
- You need continuous ingest -> detect on GCP without changing skill code
- You want a queue-driven example that can wrap any compatible `ingest-*` and
  `detect-*` pair

## What it does not do

- It is not a generic sink framework for every GCP destination
- It does not package Cloud Function archives for you
- It does not hardcode a specific skill family, detector, or downstream sink

## Required environment variables

### Ingest function

- `INGEST_SKILL_CMD`
  Example: `python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py --output-format native`
- `DETECT_TOPIC`
  Fully qualified Pub/Sub topic path such as
  `projects/my-project/topics/cloud-security-detect`

### Detect function

- `DETECT_SKILL_CMD`
  Example: `python skills/detection/detect-lateral-movement/src/detect.py --output-format native`
- `DEDUPE_COLLECTION`
  Firestore collection used for replay-safe dedupe keys
- `DEDUPE_TTL_DAYS`
  Optional retention window for dedupe documents. Defaults to `30`. The
  Terraform template also enables Firestore TTL on the `expires_at` field so
  expired rows age out automatically.
- `FINDINGS_TOPIC`
  Fully qualified Pub/Sub topic path such as
  `projects/my-project/topics/cloud-security-findings`

## Packaging model

The Terraform template expects:
- an existing source bucket name
- one GCS bucket for Cloud Function source archives
- one object name for the ingest function archive
- one object name for the detect function archive
- an explicit `max_instance_count` ceiling (defaults to `50`)

That keeps the template deployable without assuming a build system.

## Concurrency ceiling

The template exposes `max_instance_count` and defaults it to `50` for both the
ingest and detect Cloud Functions. Operators should lower or raise that ceiling
based on cost, quota, and downstream sink pressure for their environment.

## Security model

- no shell invocation; skill commands are tokenized with `shlex.split`
- `subprocess.run(..., shell=False)` only
- Firestore `create()` semantics prevent duplicate publish on replay
- dedupe rows carry `expires_at`; the template enables Firestore TTL so replay
  protection stays bounded instead of growing forever
- detect-side downstream publish keeps Pub/Sub futures outstanding until the
  batch is queued, so the client library can batch them before the handler
  waits for publish completion
- Pub/Sub findings fan-out sees only deduped findings
- operators should scope the service accounts to the specific bucket, topics,
  and Firestore collection for their environment

## Live Deploy Verification Status

Current repo reality:

- the Terraform template is shipped
- handler behavior is covered in tests
- Terraform validation runs in CI
- a checked-in real-cloud deploy-and-first-event walkthrough is still pending

That remaining deployment proof is tracked in
[`#198`](https://github.com/msaad00/cloud-ai-security-skills/issues/198).

## First Event Proof Checklist

When capturing the live walkthrough for this runner, record:

1. the exact Terraform apply inputs and deployed resources
2. the packaged Cloud Function artifacts and runtime binding
3. one object finalized in the watched GCS bucket
4. evidence that:
   - ingest function ran
   - the detect Pub/Sub topic received messages
   - detect function ran
   - a Firestore dedupe document was created
   - findings topic publish succeeded

## Prepared Walkthrough

### 1. Deploy the infrastructure

```bash
terraform -chdir=runners/gcp-gcs-pubsub-detect init
terraform -chdir=runners/gcp-gcs-pubsub-detect apply \
  -var project_id=<gcp-project-id> \
  -var region=<gcp-region> \
  -var source_bucket_name=<existing-source-bucket> \
  -var function_source_bucket=<function-archive-bucket> \
  -var ingest_source_object=<ingest-handler.zip> \
  -var detect_source_object=<detect-handler.zip> \
  -var 'ingest_skill_command=python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py --output-format native' \
  -var 'detect_skill_command=python skills/detection/detect-lateral-movement/src/detect.py --output-format native'
```

### 2. Bind the function archives

- upload the packaged ingest and detect handler archives to the
  `function_source_bucket`
- confirm both Cloud Functions point at the intended skill commands

### 3. Send one real event

```bash
gcloud storage cp sample-cloudtrail.jsonl gs://<existing-source-bucket>/incoming/sample-cloudtrail.jsonl
```

### 4. Capture proof

- Cloud Logging evidence for the ingest function invocation
- a message on the detect Pub/Sub topic
- Cloud Logging evidence for the detect function invocation
- a Firestore dedupe document with `payload_sha256` and `expires_at`
- a message on the findings topic or a downstream subscriber receipt
