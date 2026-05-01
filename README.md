# Betterleaks LLM — AI-Powered Secret Scanner

> **Fork notice:** This repository is an LLM-powered fork of [betterleaks/betterleaks](https://github.com/betterleaks/betterleaks), adding a two-phase LLM pipeline (secret discovery + false-positive verification) on top of the existing regex engine. Upstream: `git remote add upstream https://github.com/betterleaks/betterleaks`

[![upstream: betterleaks/betterleaks](https://img.shields.io/badge/upstream-betterleaks%2Fbetterleaks-blue)](https://github.com/betterleaks/betterleaks)
[![builds upon: gitleaks/gitleaks](https://img.shields.io/badge/builds%20upon-gitleaks%2Fgitleaks-green)](https://github.com/gitleaks/gitleaks)

### New in this fork

#### LLM Secret Discovery + Verification (`--llm`)

A single flag enables a two-phase LLM pipeline on top of the regex scan,
using a **locally hosted model** via [Ollama](https://ollama.com/):

1. **Discovery** — every file is scanned for lines containing credential
   keywords **or** high-entropy tokens (raw API keys, hashes, base64 blobs
   with no obvious variable name). Matching windows are sent to the LLM which
   extracts secret values the regex engine missed.

2. **Verification** — all findings (regex + discovered) are re-evaluated with
   5 lines of surrounding file context. Findings classified as `FALSE_POSITIVE`
   with confidence ≥ `--llm-min-confidence` are suppressed.

All LLM verdicts are appended to `llm_audit.jsonl` for review.

```bash
# One-time setup
ollama pull llama3        # or: mistral, codellama, etc.

# Scan any directory — findings print to stdout by default
betterleaks dir ./my-repo
betterleaks dir --llm ./my-repo

# Save structured output
betterleaks dir --llm -r findings.json ./my-repo

# Tune the pipeline
betterleaks dir --llm --llm-model mistral --llm-workers 8 ./my-repo
betterleaks dir --llm --llm-entropy-min-len 16 ./my-repo  # catch shorter keys
```

| Flag | Default | Description |
|------|---------|-------------|
| `--llm` | off | Enable LLM discovery + verification pipeline |
| `--llm-model` | `llama3` | Ollama model name |
| `--llm-host` | `http://localhost:11434` | Ollama server URL |
| `--llm-min-confidence` | `0.75` | Suppress FALSE_POSITIVE verdicts below this threshold |
| `--llm-workers` | `4` | Concurrent LLM requests during discovery |
| `--llm-entropy-min-len` | `20` | Minimum token length for entropy-based line triggering (lower = more findings, higher = fewer false positives) |

The LLM layer is **off by default** and never changes behavior without `--llm`.
If Ollama is unreachable, betterleaks warns and returns all findings unfiltered.

#### Benchmark Results (leaky-repo)

Evaluated against [leaky-repo](https://github.com/Plazmaz/leaky-repo) — 96 known
risk secrets across 42 files. Ground truth: `.leaky-meta/secrets.csv`.

| Mode | Findings | TP | FP (total) | FP (real-repo¹) | Recall | Scan time |
|------|----------|----|------------|-----------------|--------|-----------|
| Regex only | 22 | 21 | 1 | 1 | 21.9% | 0.3s |
| + `--llm` (llama3) | 362 | 84 | 278 | 77 | 87.5% | 871s |

¹ **FP (real-repo)** excludes findings in leaky-repo's own benchmark
documentation files (`.leaky-meta/`, `README.md`, `LICENSE`, `.gitattributes`,
`high-entropy-misc.txt`). These files contain credential-shaped strings
*describing* the benchmark — they are a structural artifact of this dataset and
would not exist in a real codebase.

See [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md) for the full per-file breakdown.

## Installation

This is a source-only fork. Pre-built packages (brew, dnf, Docker) are
available from [upstream betterleaks](https://github.com/betterleaks/betterleaks)
but track the upstream codebase, not this fork.

```bash
git clone https://github.com/betterleaks/betterleaks
cd betterleaks
go build -o betterleaks .
./betterleaks --version
```

Go 1.21+ required. The binary has no runtime dependencies beyond Ollama (optional, for `--llm`).

### Ollama (for `--llm`)

```bash
# Install Ollama — https://ollama.com/download
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (llama3 recommended; mistral also works well)
ollama pull llama3

# Ollama runs on http://localhost:11434 by default — no further config needed
```

## Further Reading

For full documentation on configuration, rules, allowlists, composite rules,
secrets validation (CEL), archive scanning, and all CLI flags, refer to the
[upstream betterleaks repository](https://github.com/betterleaks/betterleaks).
This fork tracks upstream and inherits all of its functionality; only the
additions described in [New in this fork](#new-in-this-fork) are specific here.
