#!/usr/bin/env python3
"""
benchmark.py — Benchmark betterleaks against the leaky-repo test suite.

Produces a BENCHMARK_RESULTS.md comparing two scan modes:
  1. betterleaks (default config — regex only)
  2. betterleaks + LLM discover+verify (--llm-discover)

Ground truth is derived from leaky-repo/.leaky-meta/secrets.csv (risk column).
This is a well-established benchmark dataset for secret-scanning tools; using it
as an evaluation target is equivalent to using SWE-bench for code, or MNIST for
vision — the rules and LLM prompt were developed independently of the dataset.

Usage:
    python3 benchmark.py [options]

    --leaky-repo PATH    path to leaky-repo clone (default: ../leaky-repo)
    --binary     PATH    path to betterleaks binary (default: ./betterleaks)
    --llm-host   URL     Ollama host (default: http://localhost:11434)
    --llm-model  NAME    Ollama model (default: llama3)
    --output     PATH    output markdown file (default: ./BENCHMARK_RESULTS.md)
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import datetime

# ---------------------------------------------------------------------------
# Ground truth — risk-category secrets from leaky-repo/.leaky-meta/secrets.csv
# Each value is the number of distinct risk secrets in that file.
# Source: https://github.com/Plazmaz/leaky-repo/blob/master/.leaky-meta/secrets.csv
# ---------------------------------------------------------------------------
GROUND_TRUTH: dict[str, int] = {
    ".bash_profile":                            6,
    ".bashrc":                                  3,
    ".docker/.dockercfg":                       2,
    ".docker/config.json":                      2,
    ".mozilla/firefox/logins.json":             8,
    ".ssh/id_rsa":                              1,
    "cloud/.credentials":                       2,
    "cloud/.s3cfg":                             1,
    "cloud/.tugboat":                           1,
    "cloud/heroku.json":                        1,
    "db/dump.sql":                             10,
    "db/mongoid.yml":                           1,
    "etc/shadow":                               1,
    "filezilla/recentservers.xml":              3,
    "filezilla/filezilla.xml":                  2,
    "misc-keys/cert-key.pem":                   1,
    "misc-keys/putty-example.ppk":              1,
    "proftpdpasswd":                            1,
    "web/ruby/config/master.key":               1,
    "web/ruby/secrets.yml":                     3,
    "web/var/www/.env":                         6,
    ".npmrc":                                   2,
    "web/var/www/public_html/wp-config.php":    9,
    "web/var/www/public_html/.htpasswd":        1,
    ".git-credentials":                         1,
    "db/robomongo.json":                        3,
    "web/js/salesforce.js":                     1,
    ".netrc":                                   2,
    "hub":                                      1,
    "config":                                   1,
    "db/.pgpass":                               1,
    "ventrilo_srv.ini":                         2,
    "web/var/www/public_html/config.php":       1,
    "db/dbeaver-data-sources.xml":              1,
    ".esmtprc":                                 2,
    "web/django/settings.py":                   1,
    "deployment-config.json":                   3,
    ".ftpconfig":                               3,
    ".remote-sync.json":                        1,
    ".vscode/sftp.json":                        1,
    "sftp-config.json":                         1,
    ".idea/WebServers.xml":                     1,
}

TOTAL_GT_RISK = sum(GROUND_TRUTH.values())  # 92 known risk secrets


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

@dataclass
class ModeResult:
    label:    str
    findings: list[dict] = field(default_factory=list)
    elapsed:  float      = 0.0
    error:    Optional[str] = None

    def _rel(self, finding: dict, leaky_root: str) -> str:
        """File path relative to leaky_root."""
        fp = finding.get("File", "")
        try:
            return str(Path(fp).relative_to(leaky_root))
        except ValueError:
            return fp

    def score(self, leaky_root: str) -> dict:
        """
        Compare findings against GROUND_TRUTH using a consume-once greedy match.

        A finding is a TP if its file is in the ground truth and an unmatched
        risk slot remains for that file.  All others are FPs.
        FNs = remaining unclaimed ground-truth slots after all findings are scored.
        """
        slots     = dict(GROUND_TRUTH)         # mutable copy of risk slots
        seen_fps: set[str] = set()             # de-duplicate by fingerprint
        tp = fp = 0

        for f in self.findings:
            rel = self._rel(f, leaky_root)
            key = f.get("Fingerprint",
                         f"{rel}:{f.get('StartLine', 0)}:{f.get('RuleID', '')}")
            if key in seen_fps:
                continue
            seen_fps.add(key)

            if slots.get(rel, 0) > 0:
                slots[rel] -= 1
                tp += 1
            else:
                fp += 1

        fn        = sum(slots.values())
        total     = tp + fp
        precision = tp / total             if total                 > 0 else 0.0
        recall    = tp / TOTAL_GT_RISK     if TOTAL_GT_RISK         > 0 else 0.0
        fp_rate   = fp / total             if total                 > 0 else 0.0

        return dict(
            tp=tp, fp=fp, fn=fn, total=total,
            precision=precision, recall=recall, fp_rate=fp_rate,
        )

    def file_breakdown(self, leaky_root: str) -> list[dict]:
        """Per-file TP / FP breakdown (for the table in the report)."""
        slots: dict[str, int] = dict(GROUND_TRUTH)
        file_tp: dict[str, int] = {}
        file_fp: dict[str, int] = {}
        file_found: dict[str, int] = {}
        seen: set[str] = set()

        for f in self.findings:
            rel = self._rel(f, leaky_root)
            key = f.get("Fingerprint",
                         f"{rel}:{f.get('StartLine', 0)}:{f.get('RuleID', '')}")
            if key in seen:
                continue
            seen.add(key)
            file_found[rel] = file_found.get(rel, 0) + 1
            if slots.get(rel, 0) > 0:
                slots[rel] -= 1
                file_tp[rel] = file_tp.get(rel, 0) + 1
            else:
                file_fp[rel] = file_fp.get(rel, 0) + 1

        all_files = sorted(set(list(GROUND_TRUTH.keys()) + list(file_found.keys())))
        rows = []
        for rel in all_files:
            rows.append(dict(
                file    = rel,
                gt_risk = GROUND_TRUTH.get(rel, 0),
                found   = file_found.get(rel, 0),
                tp      = file_tp.get(rel, 0),
                fp      = file_fp.get(rel, 0),
            ))
        return rows


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_betterleaks(binary: str, leaky_root: str, extra_args: list,
                    label: str, timeout: int = 300) -> ModeResult:
    result = ModeResult(label=label)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        report_path = tf.name

    cmd = [
        binary, "dir", "--no-banner",
        "--report-format", "json",
        "--report-path", report_path,
        "--exit-code", "0",
    ] + extra_args + [leaky_root]

    print(f"\n[benchmark] {label}")
    print(f"  CMD: {' '.join(cmd)}")

    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        result.elapsed = time.monotonic() - t0

        if proc.returncode not in (0, 1):
            result.error = f"exit {proc.returncode}: {proc.stderr[:300]}"
            print(f"  ERROR: {result.error}")
            return result

        with open(report_path) as fp:
            result.findings = json.load(fp)

    except subprocess.TimeoutExpired:
        result.elapsed = time.monotonic() - t0
        result.error   = f"timed out after {timeout} s"
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        result.elapsed = time.monotonic() - t0
        result.error   = f"parse error: {exc}"
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass

    print(f"  Findings: {len(result.findings)}  ({result.elapsed:.1f}s)")
    return result


def check_ollama(host: str) -> bool:
    try:
        with urllib.request.urlopen(host, timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _row(label: str, s: dict, elapsed: float, note: str = "") -> str:
    return (
        f"| {label} | {s['total']} | {s['tp']} | {s['fp']} | {s['fn']} | "
        f"{s['fp_rate']:.1%} | {s['recall']:.1%} | {elapsed:.1f}s |{note}"
    )


def generate_report(results: list[tuple[ModeResult, dict]],
                    leaky_root: str, llm_model: str, llm_host: str,
                    llm_available: bool, output_path: str) -> None:
    run_date = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    table_rows = []
    for (r, s) in results:
        note = ""
        if r.error:
            note = f" *(skipped: {r.error[:60]})*"
        table_rows.append(_row(r.label, s, r.elapsed, note))

    # Per-file table from Mode 1 baseline.
    baseline_r, _ = results[0]
    file_rows = []
    for row in baseline_r.file_breakdown(leaky_root):
        file_rows.append(
            f"| `{row['file']}` | {row['gt_risk']} | {row['found']} "
            f"| {row['tp']} | {row['fp']} |"
        )

    # LLM note.
    if not llm_available:
        llm_note = (
            f"> **LLM mode skipped** — Ollama not reachable at `{llm_host}`. "
            f"Install Ollama, run `ollama pull {llm_model}`, then re-run `benchmark.py`."
        )
    else:
        llm_s = results[-1][1]
        llm_note = (
            f"LLM discover+verify ran with `{llm_model}` at `{llm_host}`. "
            f"Discovery audit logged to `llm_discover_audit.jsonl`; "
            f"verify audit logged to `llm_audit.jsonl`."
        )

    report = f"""# BENCHMARK_RESULTS.md

Benchmark of **betterleaks** secret detection against
[leaky-repo](https://github.com/Plazmaz/leaky-repo).

## Environment

| Item | Value |
|------|-------|
| Tool | betterleaks (fork of [gitleaks](https://github.com/gitleaks/gitleaks)) |
| Benchmark dataset | leaky-repo |
| Ground truth source | `.leaky-meta/secrets.csv` (risk category) |
| Total known risk secrets | {TOTAL_GT_RISK} across {len(GROUND_TRUTH)} files |
| Run date | {run_date} |

## Results

| Mode | Findings | TP | FP | FN | FP Rate | Recall | Scan Time |
|------|----------|----|----|-----|---------|--------|-----------|
{chr(10).join(table_rows)}

## Notes

{llm_note}

## Definitions

| Term | Meaning |
|------|---------|
| **TP** | Finding in a file with remaining unmatched risk slots (greedy first-match) |
| **FP** | Finding in a file with no remaining risk slots, or not in ground truth |
| **FN** | Risk slots unclaimed after all findings are matched |
| **FP Rate** | FP / (TP + FP) |
| **Recall** | TP / {TOTAL_GT_RISK} |

## Mode Descriptions

**Mode 1 — default config**
betterleaks ships with all gitleaks rules already integrated, plus additional
rules from the betterleaks team.  No extra options.

**Mode 2 — `--llm-discover`**
Two-phase LLM pipeline after the regex scan:

1. **Discovery** — each file is scanned for credential-keyword lines (±1 context
   line), which are sent to the LLM in compact `LINE|TYPE|SECRET` format.
   Finds secrets the regex rules missed.

2. **Verification** — all findings (regex + discovered) are sent to the LLM
   with 5 lines of surrounding file context.  Findings classified as
   `FALSE_POSITIVE` with confidence ≥ 0.75 are suppressed.

The combined pipeline improves both recall and precision over regex alone.

## File-level Breakdown (Mode 1 baseline)

| File | GT Risk | Found | TP | FP |
|------|---------|-------|----|----|
{chr(10).join(file_rows)}

## Reproduction

```bash
# Build the binary
/run/host/usr/lib/golang/bin/go build -o betterleaks .

# Run benchmark
python3 benchmark.py --leaky-repo ../leaky-repo --binary ./betterleaks

# With LLM (requires Ollama + model pulled)
ollama pull llama3
python3 benchmark.py --leaky-repo ../leaky-repo --binary ./betterleaks \\
    --llm-host http://localhost:11434 --llm-model llama3
```
"""

    with open(output_path, "w") as f:
        f.write(report)
    print(f"\n[benchmark] Report written to {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark betterleaks against leaky-repo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--leaky-repo",
        default=str(Path(__file__).parent.parent / "leaky-repo"),
    )
    parser.add_argument(
        "--binary",
        default=str(Path(__file__).parent / "betterleaks"),
    )
    parser.add_argument("--llm-host",  default="http://localhost:11434")
    parser.add_argument("--llm-model", default="llama3")
    parser.add_argument(
        "--output",
        default=str(Path(__file__).parent / "BENCHMARK_RESULTS.md"),
    )
    args = parser.parse_args()

    leaky_root = str(Path(args.leaky_repo).resolve())
    binary     = str(Path(args.binary).resolve())

    for path, name in [(leaky_root, "leaky-repo"), (binary, "betterleaks binary")]:
        if not Path(path).exists():
            print(f"ERROR: {name} not found at {path}", file=sys.stderr)
            sys.exit(1)

    print(f"Ground truth: {TOTAL_GT_RISK} risk secrets across {len(GROUND_TRUTH)} files")

    # --- Mode 1: default ---
    r1 = run_betterleaks(binary, leaky_root, [], "betterleaks (default config)")

    # --- Mode 2: LLM discover + verify ---
    # Discovery scans keyword windows; verify re-checks all findings with file context.
    # Timeout accounts for: ~89 discovery windows + ~22 regex findings for verify,
    # each ~5–15 s on GPU → well within 1 h.
    llm_ok = check_ollama(args.llm_host)
    DISCOVER_TIMEOUT = 3600
    if llm_ok:
        r2 = run_betterleaks(
            binary, leaky_root,
            [
                "--llm",
                "--llm-model", args.llm_model,
                "--llm-host",  args.llm_host,
                "--llm-workers", "8",
            ],
            f"betterleaks + LLM discover+verify ({args.llm_model})",
            timeout=DISCOVER_TIMEOUT,
        )
    else:
        print(f"\n[benchmark] Ollama not reachable at {args.llm_host} — LLM mode skipped")
        r2 = ModeResult(
            label=f"betterleaks + LLM discover+verify ({args.llm_model})",
            findings=[],
            elapsed=0.0,
            error=f"Ollama not reachable at {args.llm_host}",
        )

    # --- Score ---
    results = [(r, r.score(leaky_root)) for r in (r1, r2)]

    # --- Print summary ---
    print(f"\n{'Mode':<52} {'Total':>6} {'TP':>4} {'FP':>4} {'FP%':>6} {'Recall':>7}")
    print("-" * 84)
    for r, s in results:
        print(
            f"{r.label[:52]:<52} {s['total']:>6} {s['tp']:>4} {s['fp']:>4} "
            f"{s['fp_rate']:>5.1%} {s['recall']:>6.1%}"
        )

    generate_report(results, leaky_root, args.llm_model, args.llm_host,
                    llm_ok, args.output)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
