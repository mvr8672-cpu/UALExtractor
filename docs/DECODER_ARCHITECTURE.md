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
