# Architecture

## Design goals

- defensive by default
- replayable locally without a live AWS account
- evidence-rich detections
- minimal moving parts in the MVP

## MVP flow

1. Load sample events from `samples/`
2. Parse and normalize them into a shared event model
3. Evaluate detection rules against the normalized stream
4. Emit findings with evidence, severity, and triage notes
5. Build a timeline grouped by principal, resource, and finding
6. Export analyst and manager summaries

## Core modules

### `ingest`

- load JSON event payloads
- identify source family
- validate required fields

### `normalize`

- map raw AWS payloads into a common event shape
- preserve raw payload references for evidence

### `detections`

- stateless and short-window correlated rules
- explicit evidence generation
- false-positive notes embedded with each rule

### `timeline`

- stitch events into incident context
- support principal- and resource-centric views

### `reporting`

- analyst incident brief
- manager summary
- finding detail export

## Storage posture

Local MVP:

- files under `samples/`
- in-memory processing
- SQLite later for notes and workflow state

Future AWS path:

- EventBridge for near-real-time routing
- S3 for raw and normalized event storage
- Athena for queryable history

## Deliberate non-goals

- broad SOAR orchestration
- generic SIEM ingestion from every source
- destructive automatic remediation
