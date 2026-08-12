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

### Current limitations

- Sprint 7 still uses sequential decoding only. Parallel decoding may be added
  later after the batch architecture is stable.
- The current helper still decodes one trace at a time and does not merge
  multiple traces internally.
- The batch decoder requires a single UFED dataset root and does not span
  multiple dataset roots in one invocation.
