from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ProvenanceValidationResult:
    component_ok: bool
    source_trace_path_ok: bool

    @property
    def ok(self) -> bool:
        return self.component_ok and self.source_trace_path_ok


class ForensicOutputError(RuntimeError):
    """Raised when forensic output cannot be prepared safely."""


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def get_git_commit(repo_root: Path) -> Optional[str]:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        )
        return completed.stdout.strip()
    except Exception:
        return None


def get_version(package_name: str) -> Optional[str]:
    try:
        # importlib.metadata in stdlib
        from importlib import metadata

        return metadata.version(package_name)
    except Exception:
        return None


def sanitize_filename_component(s: str) -> str:
    # simple sanitizer: keep alphanum, dash, underscore; replace others with _
    return "".join(c if (c.isalnum() or c in ("-", "_")) else "_" for c in s)


def _is_populated_string(value: object) -> bool:
    return isinstance(value, str) and value != ""


def validate_output_provenance(
    output_path: Path, output_format: str
) -> ProvenanceValidationResult:
    if output_format == "jsonl":
        component_ok = True
        source_trace_path_ok = True
        with output_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    return ProvenanceValidationResult(False, False)
                if not isinstance(payload, dict):
                    return ProvenanceValidationResult(False, False)
                component_ok = component_ok and _is_populated_string(
                    payload.get("component")
                )
                source_trace_path_ok = source_trace_path_ok and _is_populated_string(
                    payload.get("source_trace_path")
                )
        return ProvenanceValidationResult(component_ok, source_trace_path_ok)

    if output_format == "csv":
        with output_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = reader.fieldnames
            if fieldnames is None:
                return ProvenanceValidationResult(False, False)
            component_ok = "component" in fieldnames
            source_trace_path_ok = "source_trace_path" in fieldnames
            for row in reader:
                if component_ok:
                    component_ok = _is_populated_string(row.get("component"))
                if source_trace_path_ok:
                    source_trace_path_ok = _is_populated_string(
                        row.get("source_trace_path")
                    )
            return ProvenanceValidationResult(component_ok, source_trace_path_ok)

    raise ValueError(f"Unsupported output format for provenance validation: {output_format}")


def _ensure_writable_extraction_directory(extraction_dir: Path) -> None:
    probe_path = extraction_dir / ".ualextractor-write-probe"
    try:
        with probe_path.open("w", encoding="utf-8"):
            pass
        probe_path.unlink()
    except OSError as error:
        try:
            if probe_path.exists():
                probe_path.unlink()
        except OSError:
            pass
        try:
            extraction_dir.rmdir()
        except OSError:
            pass
        raise ForensicOutputError(
            "Downloads output is unavailable: "
            f"cannot write inside planned extraction directory {extraction_dir}: {error}"
        ) from error


def auto_output_paths(evidence_root: Path, descriptor: Optional[str], extension: str) -> tuple[Path, Path]:
    # Determine ~/Downloads, ensure it exists
    home = Path.home()
    downloads = home / "Downloads"
    try:
        downloads.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ForensicOutputError(
            "Downloads output is unavailable: "
            f"cannot access {downloads}: {error}"
        ) from error

    identifier = sanitize_filename_component(evidence_root.name)
    descriptor_part = sanitize_filename_component(descriptor) if descriptor else "output"
    date_part = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    base = f"{identifier}_{descriptor_part}_{date_part}"
    extraction_dir_name = f"UALExtractor_{base}"
    extraction_dir = downloads / extraction_dir_name

    # collision safety occurs at extraction-directory level
    i = 2
    while extraction_dir.exists():
        extraction_dir = downloads / f"{extraction_dir_name}_{i}"
        i += 1

    try:
        extraction_dir.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        raise ForensicOutputError(
            "Downloads output is unavailable: "
            f"cannot create extraction directory {extraction_dir}: {error}"
        ) from error
    _ensure_writable_extraction_directory(extraction_dir)

    filename = f"{base}.{extension.lstrip('.')}"
    out_path = extraction_dir / filename

    # validation filename remains paired inside the extraction directory
    report_name = f"{base}_validation.txt"
    report_path = extraction_dir / report_name
    return out_path, report_path


def write_validation_report(
    report_path: Path,
    *,
    dataset_identifier: str,
    evidence_root: Path,
    output_path: Path,
    output_format: str,
    components: list[str],
    decoder_path: Path,
    start_time: str,
    end_time: str,
    elapsed_seconds: float,
    filter_spec_repr: str,
    trace_results: list[dict],
    records_decoded: int,
    records_matched: int,
    records_filtered_out: int,
    component_provenance_ok: bool,
    source_trace_path_provenance_ok: bool,
) -> None:
    # compute output integrity
    try:
        size = output_path.stat().st_size
        sha256 = compute_sha256(output_path)
    except Exception:
        size = None
        sha256 = "unavailable"

    invariant_ok = (records_decoded == (records_matched + records_filtered_out))

    with report_path.open("w", encoding="utf-8", newline="") as f:
        f.write("UALExtractor — Extraction Validation Report\n")
        f.write("\n")
        f.write("[Identification]\n")
        f.write(f"dataset identifier: {dataset_identifier}\n")
        f.write(f"evidence root: {evidence_root}\n")
        f.write(f"output filename: {output_path.name}\n")
        f.write(f"output absolute path: {output_path.resolve()}\n")
        f.write(f"output format: {output_format}\n")
        f.write(f"component(s): {', '.join(components)}\n")
        f.write("\n")
        f.write("[Tool information]\n")
        ver = get_version("ualextractor") or "unavailable"
        f.write(f"UALExtractor version: {ver}\n")
        # git commit
        repo_root = Path(__file__).resolve().parents[2]
        git_commit = get_git_commit(repo_root) or "unavailable"
        f.write(f"git commit: {git_commit}\n")
        f.write(f"decoder path: {decoder_path}\n")
        f.write(f"execution start: {start_time}\n")
        f.write(f"execution end: {end_time}\n")
        f.write(f"elapsed seconds: {elapsed_seconds:.2f}\n")
        f.write("\n")
        f.write("[Filter specification]\n")
        f.write(filter_spec_repr + "\n")
        f.write("\n")
        f.write("[Trace processing]\n")
        f.write(f"traces attempted: {len(trace_results)}\n")
        f.write(f"traces succeeded: {sum(1 for t in trace_results if t.get('succeeded'))}\n")
        f.write(f"traces failed: {sum(1 for t in trace_results if not t.get('succeeded'))}\n")
        f.write("\n")
        for t in trace_results:
            f.write(f"- component: {t.get('component')}\n")
            f.write(f"  source_trace_path: {t.get('trace_path')}\n")
            f.write(f"  records decoded: {t.get('records_decoded')}\n")
            f.write(f"  records matched: {t.get('records_matched')}\n")
            f.write(f"  records filtered out: {t.get('records_filtered_out')}\n")
            f.write(f"  succeeded: {t.get('succeeded')}\n")
            if t.get('diagnostics'):
                f.write("  diagnostics:\n")
                for d in t.get('diagnostics'):
                    f.write(f"    {d}\n")
        f.write("\n")
        f.write("[Record accounting]\n")
        f.write(f"records_decoded: {records_decoded}\n")
        f.write(f"records_matched: {records_matched}\n")
        f.write(f"records_filtered_out: {records_filtered_out}\n")
        f.write("\n")
        f.write(f"Counter invariant: {'PASS' if invariant_ok else 'FAIL'}\n")
        f.write("\n")
        f.write("[Provenance validation]\n")
        f.write(
            "component populated/preserved: "
            f"{'PASS' if component_provenance_ok else 'FAIL'}\n"
        )
        f.write(
            "source_trace_path populated/preserved: "
            f"{'PASS' if source_trace_path_provenance_ok else 'FAIL'}\n"
        )
        f.write("\n")
        f.write("[Output integrity]\n")
        f.write("Algorithm: SHA-256\n")
        f.write(f"File: {output_path}\n")
        f.write(f"Size: {size if size is not None else 'unavailable'}\n")
        f.write(f"SHA-256: {sha256}\n")
        f.write("\n")
        # final result
        overall_ok = (
            invariant_ok
            and all(t.get('succeeded') for t in trace_results)
            and component_provenance_ok
            and source_trace_path_provenance_ok
            and sha256 != 'unavailable'
        )
        f.write(f"VALIDATION: {'PASS' if overall_ok else 'FAIL'}\n")
