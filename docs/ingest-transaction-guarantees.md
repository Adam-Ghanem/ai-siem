# Atomic ingest constraint handling

The SQLite ingest transaction writes events and derived alerts together. An
existing ID is treated as an idempotent replay only when its stored payload
matches the submitted payload exactly.

Previously, `INSERT OR IGNORE` also suppressed non-ID constraints (for example
an invalid NOT NULL alert field). That could commit an event while silently
dropping its alert. Ingest now uses `ON CONFLICT(id) DO NOTHING` and
`ON CONFLICT(alert_id) DO NOTHING`, so only primary-key replays can be
ignored. Missing persisted rows after an ignored insert cause a rollback and
`IngestCommitRace` rather than a partial success.

Regression tests cover NOT NULL violations on events and alerts, a trigger
that silently ignores an alert, and exact-ID replay.

This is a **single SQLite transaction** guarantee, not a distributed delivery
or exactly-once ingestion guarantee. The collector, API, in-memory hot window,
and downstream incident lifecycle still need a durable queue, stable source
identities, replay handling, and multi-worker coordination before enterprise
scale.
