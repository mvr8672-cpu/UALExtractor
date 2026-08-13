# Decoder architecture

UALExtractor uses a small Rust helper around Mandiant's
`macos-unifiedlogs` crate (`0.6.0`) as its Unified Log decoder backend.
The Python application invokes the helper through `subprocess` and exchanges
records as JSON Lines (JSONL).

The helper accepts UFED evidence paths directly through an explicit adapter:

- `db/diagnostics`
- `db/uuidtext`
- `db/uuidtext/dsc`
- `db/diagnostics/timesync`
- one selected `.tracev3` path

The adapter opens evidence only for reading. It does not create a
`.logarchive`, copy evidence, or write generated output into the evidence
tree. JSONL records are written to stdout; parser diagnostics are written to
stderr so the two channels remain independent.

The Sprint 6 proof of concept intentionally decodes one trace only. Automatic
selection prefers `HighVolume`; `Persist` is used only when no HighVolume trace
is available. Within the preferred component, selection is deterministic by
file size and then full path. Bulk decoding, filtering, export, and database
storage are outside Sprint 6.

## Validated proof of concept

Two controlled read-only runs against the development UFED export validated
the direct UFED-to-Rust-to-JSONL path:

- HighVolume: one trace, 243 records, exit code 0, reconstructed messages,
  and no stderr diagnostics.
- Persist: one trace, 350,815 records, exit code 0, one source trace path,
  populated PID fields for all records, populated process fields for 350,536
  records, populated subsystem fields for 257,640 records, populated
  category fields for 250,522 records, and populated messages for 350,750
  records. No stderr diagnostics were emitted.

These results validate the decoder path without committing decoded evidence,
including log messages, to the repository.

## Batch decoding architecture

Sprint 7 adds a Python batch orchestration layer on top of the single-trace
Rust helper. The helper remains unchanged and continues to decode exactly one
trace at a time.

The batch architecture is intentionally safe and deterministic:

- Batch decoding is explicit. Users must request specific components with
  `--component`. There is no implicit "decode everything" default.
- Trace ordering is canonical: `HighVolume`, `Persist`, `Signpost`, then
  `Special`, and within each component traces are sorted by full path.
- Records are streamed incrementally. The batch decoder writes JSONL as each
  record arrives and retains only per-trace counters in memory.
- Diagnostics and progress are kept on stderr. JSONL output remains machine-
  readable and is never polluted with diagnostic text.
- Each trace is isolated: exits, parsing failures, or malformed records for
  one trace are reported in the batch summary without corrupting other traces.
- If a trace emits malformed JSONL, the batch marks that trace as failed,
  records the failure, and continues with the next trace by default.
- Output file creation is protected. Existing files are not overwritten unless
  `--force` is provided.

## Sprint 8 filtering architecture

Sprint 8 adds a Python-side filtering layer to the existing streaming batch
pipeline. The Rust helper remains a minimal decoder boundary and continues to
emit one decoded JSONL record at a time. The Python orchestration layer reads
that JSONL stream, applies a filter predicate, writes only matching records to
stdout or the selected output file, and discards non-matching records
immediately.

The filter contract is intentionally simple and forensic-friendly:

- Different filter types combine with logical AND.
- Repeated values for the same filter type combine with logical OR.
- Filter evaluation is deterministic and timezone-aware.
- Provenance is preserved: `source_trace_path` and `component` remain attached
  to every emitted record.
- The decoded record content is not rewritten. Filtering only decides whether a
  record is emitted.

## Sprint 8 forensic output packaging

Sprint 8 also adds a forensic output packaging layer for `decode --downloads`.
That path now creates one self-contained extraction directory per run under
`~/Downloads`:

- `UALExtractor_<dataset>_<descriptor>_<utc-date>/`
- collision handling occurs at the extraction-directory level using `_2`, `_3`,
  and so on
- the decoded output file and paired validation report are written together
  inside that directory

Before any decoder subprocess starts, the Python layer prepares the intended
Downloads destination and verifies that the planned extraction directory can be
created and written. This is especially important on macOS, where TCC/privacy
prompts may deny Downloads access.

The implementation intentionally does **not**:

- modify macOS permissions programmatically
- bypass TCC/privacy protections
- require Full Disk Access
- silently fall back to another output directory

If Downloads access is unavailable or the extraction directory is not writable,
the command fails before decoding begins, reports a clear diagnostic on stderr,
starts no decoder subprocess, and leaves no partial extraction package behind.

## Sprint 8 forensic validation report

The validation report records execution provenance and derived-output integrity:

- execution start timestamp (timezone-aware ISO-8601, captured before decoding)
- execution end timestamp (timezone-aware ISO-8601, captured after decoding)
- elapsed seconds
- per-trace accounting
- record-accounting invariant
- output byte size
- output SHA-256
- emitted-record provenance validation for both JSONL and CSV outputs

Provenance validation is format-aware and checks every emitted record. The
report fails if any emitted record is missing or has an empty `component` or
`source_trace_path` field.

### Supported filters

The existing `decode` command accepts:

- `--start`
- `--end`
- `--process`
- `--pid`
- `--subsystem`
- `--category`
- `--event-type`
- `--log-type`
- `--contains`

String filters are case-insensitive and use substring matching unless the field
is a controlled exact vocabulary (`event_type`, `log_type`, and `pid`).
`--contains` searches the human-readable fields `message`, `process`,
`subsystem`, and `category` to keep forensic triage practical without needing a
separate post-processing stage.

### Timestamp semantics

Timestamps are parsed as timezone-aware ISO-8601 values or date-only values.
Date-only values are converted to UTC boundaries deterministically:

- `--start 2026-05-02` means `>= 2026-05-02T00:00:00Z`
- `--end 2026-05-02` means `< 2026-05-03T00:00:00Z`
- explicit timestamps remain inclusive:
  `timestamp <= 2026-05-02T06:00:00Z`

The batch rejects naive timestamps without timezone information and rejects
invalid ranges before starting any decoder subprocess.

### Counter model

The batch summary preserves Sprint 7 counters and adds filter-level totals:

- `records_decoded`: all successfully parsed decoder records considered by the
  filtering layer
- `records_matched`: records that pass the filter and are emitted
- `records_filtered_out`: records parsed successfully but discarded by the filter

The invariant holds:

`records_decoded == records_matched + records_filtered_out`

### Current limitations

- Batch decoding remains sequential. Parallel decode processing is not yet in
  scope for Sprint 8.
- The current helper still decodes one trace at a time and does not merge
  multiple traces internally.
- The batch decoder requires a single UFED dataset root and does not span
  multiple dataset roots in one invocation.
