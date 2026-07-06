# aws-s3-sqs-detect

Reference persistent runner template for continuous ingest → detect pipelines on
AWS. The template attaches to an existing source bucket and keeps the queue,
dedupe table, and alert path inside the stack.

## What it does

```
S3 object create
  -> ingest Lambda
  -> SQS queue
  -> detect Lambda
  -> DynamoDB dedupe
  -> SNS fan-out
```

The runner keeps state and side effects at the edges:
- S3 is the raw object source
- SQS provides durable decoupling
- DynamoDB stores replay-safe dedupe keys
- SNS distributes new findings downstream

The skills remain unchanged and stateless.

## When to use it

- You want a repo-owned example of a persistent execution path beyond IAM departures
- You need a minimal AWS pattern for continuous ingest → detect with replay safety
- You want to wire any compatible `ingest-*` and `detect-*` skill pair into a
  queue-driven loop

## What it does not do

- It is not a generic sink framework for every cloud or SIEM
- It does not package Lambda zip artifacts for you
- It does not hardcode a specific skill family, sink vendor, or storage format

## Required environment variables

### Ingest Lambda

- `INGEST_SKILL_CMD`
  Example: `python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py --output-format native`
- `DETECT_QUEUE_URL`

### Detect Lambda

- `DETECT_SKILL_CMD`
  Example: `python skills/detection/detect-lateral-movement/src/detect.py --output-format native`
- `DEDUPE_TABLE`
- `DEDUPE_TTL_DAYS` (optional, default 30, range 1-365). Controls how long dedupe rows live before DynamoDB TTL expires them.
- `SNS_TOPIC_ARN`

## Packaging model

The CloudFormation template expects:
- an existing source bucket name
- one zip for the ingest handler
- one zip for the detect handler

That keeps the template deployable without assuming SAM or an external build
system.

## Security model

- no shell invocation; skill commands are tokenized with `shlex.split`
- `subprocess.run(..., shell=False)` only
- DynamoDB conditional writes prevent duplicate publish on replay
- detect-side downstream fan-out uses SNS `publish_batch` in batches of up to
  `10` findings per API call instead of one publish call per finding
- DynamoDB TTL is enabled with an `expires_at` attribute on every new dedupe
  row. The `DedupeTtlDays` CloudFormation parameter (default 30, range 1-365)
  flows into the detect Lambda as `DEDUPE_TTL_DAYS` and controls how long a
  UID stays suppressed before DynamoDB deletes the row and a recurrence is
  allowed to re-fire. Rows written before TTL was enabled are not backfilled
  and will remain until they are overwritten or removed manually.
- SNS only sees deduped findings
- operators should scope the Lambda roles to the specific source bucket, queue,
  topic, and table ARNs in their environment

## Live Deploy Verification Status

Current repo reality:

- the template is shipped
- handler behavior is covered in tests
- infrastructure validation runs in CI
- a checked-in real-cloud deploy-and-first-event walkthrough is still pending

That remaining deployment proof is tracked in
[`#198`](https://github.com/msaad00/cloud-ai-security-skills/issues/198).

## First Event Proof Checklist

When capturing the live walkthrough for this runner, record:

1. the exact CloudFormation deploy command and parameters
2. the source bucket notification binding
3. one uploaded object that triggers the ingest path
4. evidence that:
   - ingest Lambda ran
   - an SQS detect message was created
   - detect Lambda ran
   - a DynamoDB dedupe row was written
   - an SNS publish succeeded

## Prepared Walkthrough

### 1. Deploy the stack

```bash
aws cloudformation deploy \
  --template-file runners/aws-s3-sqs-detect/template.yaml \
  --stack-name cloud-security-runner-aws \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      SourceBucketName=<existing-source-bucket> \
      IngestHandlerZipKey=<ingest-handler.zip> \
      DetectHandlerZipKey=<detect-handler.zip> \
      IngestSkillCommand="python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py --output-format native" \
      DetectSkillCommand="python skills/detection/detect-lateral-movement/src/detect.py --output-format native"
```

### 2. Bind the source event

- enable the source bucket notification so object-create events invoke the
  ingest Lambda shipped by this stack

### 3. Send one real event

```bash
aws s3 cp sample-cloudtrail.jsonl s3://<existing-source-bucket>/incoming/sample-cloudtrail.jsonl
```

### 4. Capture proof

- CloudWatch log lines showing the ingest Lambda invocation
- an SQS message in the detect queue
- CloudWatch log lines showing the detect Lambda invocation
- a DynamoDB item in the dedupe table with `pk`, `payload_sha256`, and `expires_at`
- an SNS message or subscriber receipt proving the downstream publish
