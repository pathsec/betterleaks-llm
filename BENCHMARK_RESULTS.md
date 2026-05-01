# BENCHMARK_RESULTS.md

Benchmark of **betterleaks** secret detection against
[leaky-repo](https://github.com/Plazmaz/leaky-repo).

## Environment

| Item | Value |
|------|-------|
| Tool | betterleaks (fork of [gitleaks](https://github.com/gitleaks/gitleaks)) |
| Benchmark dataset | leaky-repo |
| Ground truth source | `.leaky-meta/secrets.csv` (risk category) |
| Total known risk secrets | 96 across 42 files |
| Run date | 2026-05-01 13:43 UTC |

## Results

| Mode | Findings | TP | FP | FN | FP Rate | Recall | Scan Time |
|------|----------|----|----|-----|---------|--------|-----------|
| betterleaks (default config) | 22 | 21 | 1 | 75 | 4.5% | 21.9% | 0.3s |
| betterleaks + LLM discover+verify (llama3) | 362 | 84 | 278 | 12 | 76.8% | 87.5% | 871.2s |

## Notes

LLM discover+verify ran with `llama3` at `http://localhost:11434`. Discovery audit logged to `llm_discover_audit.jsonl`; verify audit logged to `llm_audit.jsonl`.

## Definitions

| Term | Meaning |
|------|---------|
| **TP** | Finding in a file with remaining unmatched risk slots (greedy first-match) |
| **FP** | Finding in a file with no remaining risk slots, or not in ground truth |
| **FN** | Risk slots unclaimed after all findings are matched |
| **FP Rate** | FP / (TP + FP) |
| **Recall** | TP / 96 |

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
| `.bash_profile` | 6 | 3 | 3 | 0 |
| `.bashrc` | 3 | 2 | 2 | 0 |
| `.docker/.dockercfg` | 2 | 2 | 2 | 0 |
| `.docker/config.json` | 2 | 2 | 2 | 0 |
| `.esmtprc` | 2 | 0 | 0 | 0 |
| `.ftpconfig` | 3 | 0 | 0 | 0 |
| `.git-credentials` | 1 | 0 | 0 | 0 |
| `.idea/WebServers.xml` | 1 | 0 | 0 | 0 |
| `.mozilla/firefox/logins.json` | 8 | 0 | 0 | 0 |
| `.netrc` | 2 | 0 | 0 | 0 |
| `.npmrc` | 2 | 1 | 1 | 0 |
| `.remote-sync.json` | 1 | 0 | 0 | 0 |
| `.ssh/id_rsa` | 1 | 1 | 1 | 0 |
| `.vscode/sftp.json` | 1 | 0 | 0 | 0 |
| `cloud/.credentials` | 2 | 2 | 2 | 0 |
| `cloud/.s3cfg` | 1 | 2 | 1 | 1 |
| `cloud/.tugboat` | 1 | 1 | 1 | 0 |
| `cloud/heroku.json` | 1 | 1 | 1 | 0 |
| `config` | 1 | 0 | 0 | 0 |
| `db/.pgpass` | 1 | 0 | 0 | 0 |
| `db/dbeaver-data-sources.xml` | 1 | 0 | 0 | 0 |
| `db/dump.sql` | 10 | 0 | 0 | 0 |
| `db/mongoid.yml` | 1 | 0 | 0 | 0 |
| `db/robomongo.json` | 3 | 0 | 0 | 0 |
| `deployment-config.json` | 3 | 0 | 0 | 0 |
| `etc/shadow` | 1 | 0 | 0 | 0 |
| `filezilla/filezilla.xml` | 2 | 0 | 0 | 0 |
| `filezilla/recentservers.xml` | 3 | 0 | 0 | 0 |
| `hub` | 1 | 1 | 1 | 0 |
| `misc-keys/cert-key.pem` | 1 | 1 | 1 | 0 |
| `misc-keys/putty-example.ppk` | 1 | 0 | 0 | 0 |
| `proftpdpasswd` | 1 | 0 | 0 | 0 |
| `sftp-config.json` | 1 | 0 | 0 | 0 |
| `ventrilo_srv.ini` | 2 | 0 | 0 | 0 |
| `web/django/settings.py` | 1 | 0 | 0 | 0 |
| `web/js/salesforce.js` | 1 | 0 | 0 | 0 |
| `web/ruby/config/master.key` | 1 | 0 | 0 | 0 |
| `web/ruby/secrets.yml` | 3 | 3 | 3 | 0 |
| `web/var/www/.env` | 6 | 0 | 0 | 0 |
| `web/var/www/public_html/.htpasswd` | 1 | 0 | 0 | 0 |
| `web/var/www/public_html/config.php` | 1 | 0 | 0 | 0 |
| `web/var/www/public_html/wp-config.php` | 9 | 0 | 0 | 0 |

## Reproduction

```bash
# Build the binary
/run/host/usr/lib/golang/bin/go build -o betterleaks .

# Run benchmark
python3 benchmark.py --leaky-repo ../leaky-repo --binary ./betterleaks

# With LLM (requires Ollama + model pulled)
ollama pull llama3
python3 benchmark.py --leaky-repo ../leaky-repo --binary ./betterleaks \
    --llm-host http://localhost:11434 --llm-model llama3
```
