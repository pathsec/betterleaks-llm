# Changelog

All notable changes to this fork of [betterleaks/betterleaks](https://github.com/betterleaks/betterleaks) are documented here.

## [Unreleased] — 2026-03-20

### Added

#### Phase 3 — LLM False-Positive Reduction Layer

- **`llm/verify.go`** — new `llm` package implementing an Ollama-based post-scan
  false-positive filter.
  - `FilterFalsePositives()` batches findings to a local LLM via the Ollama
    `/api/generate` API.
  - Each finding is presented with file path, line number, matched line, rule ID,
    and entropy score using a structured prompt that describes what real credentials
    look like in principle (not calibrated against any benchmark dataset).
  - Findings returned as `FALSE_POSITIVE` with `confidence ≥ 0.75` are suppressed.
  - Graceful fallback: if Ollama is unreachable the layer warns and returns all
    findings unfiltered — no behavior change from the user's perspective.
  - All LLM verdicts (verdict, confidence, reasoning, fingerprint) are appended
    to `llm_audit.jsonl` for human review and auditability.

- **`--llm-verify`** persistent flag — enables the LLM layer (off by default).
- **`--llm-model`** persistent flag — Ollama model name (default: `llama3`).
- **`--llm-host`** persistent flag — Ollama server URL (default: `http://localhost:11434`).
- **`--llm-min-confidence`** persistent flag — minimum confidence threshold to
  act on a `FALSE_POSITIVE` verdict (default: `0.75`).

#### Phase 4 — Benchmark Harness

- **`benchmark.py`** — Python benchmark script evaluating betterleaks against
  [leaky-repo](https://github.com/Plazmaz/leaky-repo).
  - Runs two modes: default config and `--llm-verify`.
  - Scores findings against the leaky-repo ground truth
    (`.leaky-meta/secrets.csv`, risk category — 96 known risk secrets across 42 files).
  - Prints a per-mode summary table (TP, FP, FP rate, recall, scan time).
  - Writes `BENCHMARK_RESULTS.md` with a per-file breakdown.

- **`BENCHMARK_RESULTS.md`** — generated benchmark report.

#### Phase 5 — Documentation

- **`README.md`** — updated with:
  - Fork/upstream attribution header and badges.
  - "New in this fork" section documenting `--llm-verify` and the benchmark results.
  - Ollama installation instructions.
  - Link to `BENCHMARK_RESULTS.md`.

- **`CHANGELOG.md`** — this file.

### Changed

- `cmd/root.go` — added persistent flags (`--llm-verify`, `--llm-model`,
  `--llm-host`, `--llm-min-confidence`) and the LLM filtering step inside
  `findingSummaryAndExit()`.

### Notes

- All gitleaks detection rules were already integrated into betterleaks prior to
  this fork; no rule migration was required.
- Shannon entropy scanning, allowlist support (path globs, regex stop patterns,
  commit SHA ignores), and gitleaks TOML compatibility were already present.
- The LLM layer is strictly additive and opt-in — existing scan behavior is
  identical when `--llm-verify` is not passed.
