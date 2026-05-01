// Package llm — this file implements LLM-assisted secret discovery.
//
// DiscoverSecrets walks a source path, sends credential-adjacent line windows
// to a locally hosted LLM, and returns secrets the regex engine missed.
//
// Activate with:  betterleaks dir --llm [path]
package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
)

const (
	// DiscoverAuditLogFile collects everything the LLM surfaced (new + confirmed).
	DiscoverAuditLogFile = "llm_discover_audit.jsonl"

	discoverQuickTimeout = 60 * time.Second // fail fast if LLM is slow on a small excerpt

	// DefaultDiscoverWorkers is the default number of concurrent LLM calls.
	DefaultDiscoverWorkers = 4

	quickContextLines = 1 // lines of context before/after each keyword hit

	// DefaultEntropyMinLen is the default minimum token length for entropy-based
	// secret detection.  Overridden at runtime by --llm-entropy-min-len.
	// Lower values surface more candidates (higher recall, more LLM calls);
	// higher values are more conservative (fewer false positives).
	DefaultEntropyMinLen = 20  // characters — shorter tokens are usually plain words
	entropyMinBits       = 3.5 // bits/char — most key/hash formats exceed this
)

// DiscoveredSecret is the per-finding result from the quick discovery pass.
type DiscoveredSecret struct {
	Line       int     `json:"line"`
	Secret     string  `json:"secret"`
	Type       string  `json:"type"`
	Confidence float64 `json:"confidence"`
	Context    string  `json:"context"` // the raw source line
}

// DiscoverAuditEntry records one LLM-discovered finding for later review.
type DiscoverAuditEntry struct {
	Timestamp   string  `json:"timestamp"`
	File        string  `json:"file"`
	Line        int     `json:"line"`
	Type        string  `json:"type"`
	Secret      string  `json:"secret"`
	Entropy     float32 `json:"entropy"`
	Confidence  float64 `json:"confidence"`
	Fingerprint string  `json:"fingerprint"`
	IsNew       bool    `json:"is_new"` // true = not caught by regex rules
}

// credKeywords are lowercase substrings that suggest a line may contain
// credential material. Lines with none of these are skipped.
var credKeywords = []string{
	"password", "passwd", "passphrase", "secret", "token", "api_key", "apikey",
	"access_key", "auth", "credential", "private_key", "private key",
	"BEGIN RSA", "BEGIN EC", "BEGIN OPENSSH", "BEGIN PGP",
	"client_secret", "encryption_key", "encryption key",
	"smtp_pass", "db_pass", "database_pass",
}

// binaryExtensions is a fast-reject set to skip files unlikely to contain
// text-based secrets.
var binaryExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".bmp": true, ".ico": true, ".pdf": true,
	".zip": true, ".gz": true, ".tar": true, ".bz2": true,
	".xz": true, ".7z": true, ".rar": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".bin": true, ".o": true, ".a": true,
	".ttf": true, ".woff": true, ".woff2": true, ".eot": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
	".db": true, ".sqlite": true, ".idx": true, ".pack": true,
}

// DiscoverSecrets walks sourcePath, sends credential-keyword line windows to
// the LLM using a concurrent worker pool, and returns findings not already
// caught by existingFindings.  Findings with confidence < cfg.MinConf are
// dropped.  All hits are written to DiscoverAuditLogFile.
func DiscoverSecrets(ctx context.Context, sourcePath string,
	cfg Config, existingFindings []report.Finding) []report.Finding {

	if sourcePath == "" {
		return nil
	}

	// Defaults.
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	if cfg.Host == "" {
		cfg.Host = DefaultHost
	}
	if cfg.MinConf == 0 {
		cfg.MinConf = 0.5 // lower default for discovery (recall over precision)
	}
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultDiscoverWorkers
	}

	if !ping(ctx, cfg.Host) {
		logging.Warn().Str("host", cfg.Host).
			Msg("LLM discover: Ollama unreachable, skipping discovery")
		return nil
	}

	// Build a set of (file:line:secret) already found by regex rules.
	existingSet := make(map[string]struct{}, len(existingFindings))
	for _, f := range existingFindings {
		existingSet[existingKey(f.File, f.StartLine, f.Secret)] = struct{}{}
	}

	auditFile, err := os.OpenFile(DiscoverAuditLogFile,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		logging.Warn().Err(err).Msgf("LLM discover: cannot open audit log %s", DiscoverAuditLogFile)
		auditFile = nil
	}
	if auditFile != nil {
		defer func() { _ = auditFile.Close() }()
	}

	// Collect all candidate file paths first, then process concurrently.
	var filePaths []string
	_ = filepath.WalkDir(sourcePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == ".svn" || name == ".hg" {
				return filepath.SkipDir
			}
			return nil
		}
		if binaryExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if info, statErr := d.Info(); statErr == nil && info.Size() > 512*1024 {
			logging.Debug().Str("file", path).Msg("LLM discover: skipping large file")
			return nil
		}
		filePaths = append(filePaths, path)
		return nil
	})

	logging.Info().
		Int("files", len(filePaths)).
		Int("workers", cfg.Workers).
		Msg("LLM discover: starting concurrent scan")

	type fileResult struct {
		path    string
		secrets []DiscoveredSecret
	}

	fileCh := make(chan string, len(filePaths))
	for _, p := range filePaths {
		fileCh <- p
	}
	close(fileCh)

	resultCh := make(chan fileResult, len(filePaths))
	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileCh {
				discovered := processFile(ctx, path, cfg)
				resultCh <- fileResult{path: path, secrets: discovered}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results (single goroutine — safe to write to auditFile).
	var newFindings []report.Finding
	for res := range resultCh {
		for _, ds := range res.secrets {
			if ds.Confidence < cfg.MinConf || strings.TrimSpace(ds.Secret) == "" {
				continue
			}

			entropy := shannonEntropyF32(ds.Secret)
			fp := fingerprintDiscover(res.path, ds.Line, ds.Secret)
			isNew := false

			if _, found := existingSet[existingKey(res.path, ds.Line, ds.Secret)]; !found {
				isNew = true
				newFindings = append(newFindings, report.Finding{
					RuleID:      "llm-discovered",
					Description: fmt.Sprintf("LLM-discovered secret: %s", ds.Type),
					StartLine:   ds.Line,
					EndLine:     ds.Line,
					Line:        ds.Context,
					Match:       ds.Context,
					Secret:      ds.Secret,
					File:        res.path,
					Entropy:     entropy,
					Tags:        []string{"llm", "llm-discover"},
					Fingerprint: fp,
				})
			}

			writeDiscoverAudit(auditFile, DiscoverAuditEntry{
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				File:        res.path,
				Line:        ds.Line,
				Type:        ds.Type,
				Secret:      ds.Secret,
				Entropy:     entropy,
				Confidence:  ds.Confidence,
				Fingerprint: fp,
				IsNew:       isNew,
			})
		}
	}

	if len(newFindings) > 0 {
		logging.Info().
			Int("new_findings", len(newFindings)).
			Str("audit_log", DiscoverAuditLogFile).
			Msg("LLM discover: secrets found beyond regex rules")
	} else {
		logging.Info().Msg("LLM discover: no additional secrets found beyond regex rules")
	}

	return newFindings
}

// suspiciousWindow is a contiguous excerpt of lines that contains at least one
// credential keyword, plus up to quickContextLines of surrounding context.
type suspiciousWindow struct {
	lineBase int      // 1-based line number of the first line in the window
	lines    []string // the actual lines
}

// extractSuspiciousWindows scans lines for credential keywords or high-entropy
// tokens and returns merged windows of those lines plus context.
// minLen is forwarded to lineIsSuspicious (0 = use default).
func extractSuspiciousWindows(lines []string, minLen int) []suspiciousWindow {
	var windows []suspiciousWindow
	for i, line := range lines {
		if !lineIsSuspicious(line, minLen) {
			continue
		}
		start := i - quickContextLines
		if start < 0 {
			start = 0
		}
		end := i + quickContextLines + 1
		if end > len(lines) {
			end = len(lines)
		}
		// Merge with the previous window if they overlap or are adjacent.
		if len(windows) > 0 {
			prev := &windows[len(windows)-1]
			prevEnd := prev.lineBase - 1 + len(prev.lines) // exclusive, 0-based
			if start <= prevEnd {
				newEnd := end
				if prevEnd > newEnd {
					newEnd = prevEnd
				}
				prev.lines = lines[prev.lineBase-1 : newEnd]
				continue
			}
		}
		windows = append(windows, suspiciousWindow{
			lineBase: start + 1, // convert to 1-based
			lines:    lines[start:end],
		})
	}
	return windows
}

// lineIsSuspicious returns true if the line contains a credential keyword OR a
// high-entropy token.  The entropy check is what lets the LLM see raw secrets
// that live next to generic variable names (e.g. `x = "AKIAIOSFODNN7EXAMPLE"`).
// minLen overrides entropyMinLen when > 0.
func lineIsSuspicious(line string, minLen int) bool {
	return lineHasCredKeyword(line) || lineHasSuspiciousToken(line, minLen)
}

// lineHasCredKeyword returns true if the line contains a known credential keyword.
func lineHasCredKeyword(line string) bool {
	lower := strings.ToLower(line)
	for _, kw := range credKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// lineHasSuspiciousToken returns true if any token on the line is long enough
// and has high enough Shannon entropy to suggest it is a raw secret value.
// minLen overrides the entropyMinLen constant when > 0 (set via --llm-entropy-min-len).
func lineHasSuspiciousToken(line string, minLen int) bool {
	threshold := DefaultEntropyMinLen
	if minLen > 0 {
		threshold = minLen
	}
	for _, tok := range strings.FieldsFunc(line, isTokenSep) {
		if len(tok) >= threshold && tokenEntropy(tok) >= entropyMinBits {
			return true
		}
	}
	return false
}

// isTokenSep reports whether r is a character that separates key from value in
// common config file formats (shell, YAML, JSON, TOML, .env, XML attributes).
func isTokenSep(r rune) bool {
	switch r {
	case ' ', '\t', '=', ':', '"', '\'', ',', ';', '{', '}', '(', ')', '[', ']', '<', '>':
		return true
	}
	return false
}

// tokenEntropy computes Shannon entropy (bits/char) for a single token.
func tokenEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int, 64)
	for _, r := range s {
		counts[r]++
	}
	inv := 1.0 / float64(len(s))
	var h float64
	for _, c := range counts {
		p := float64(c) * inv
		h -= p * math.Log2(p)
	}
	return h
}

// processFile reads a file and collects discovered secrets by sending
// credential-keyword line windows to the LLM.
func processFile(ctx context.Context, path string, cfg Config) []DiscoveredSecret {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Quick binary-content heuristic: >30 % non-printable bytes → skip.
	sample := data
	if len(sample) > 512 {
		sample = sample[:512]
	}
	nonPrint := 0
	for _, b := range sample {
		if b < 0x09 || (b > 0x0d && b < 0x20) || b == 0x7f {
			nonPrint++
		}
	}
	if len(sample) > 0 && float64(nonPrint)/float64(len(sample)) > 0.30 {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	windows := extractSuspiciousWindows(lines, cfg.EntropyMinLen)
	if len(windows) == 0 {
		return nil
	}

	seen := make(map[string]struct{}) // dedup key: "line:secret"
	var all []DiscoveredSecret
	for _, w := range windows {
		secrets, chunkErr := discoverInChunk(ctx, path,
			strings.Join(w.lines, "\n"), w.lineBase, cfg)
		if chunkErr != nil {
			logging.Debug().Err(chunkErr).Str("file", path).
				Int("line_base", w.lineBase).Msg("LLM discover: chunk error")
		}
		for _, s := range secrets {
			key := fmt.Sprintf("%d:%s", s.Line, strings.ToLower(strings.TrimSpace(s.Secret)))
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			all = append(all, s)
		}
	}
	return all
}

// discoverInChunk sends a credential-keyword window to the LLM using a compact
// pipe-delimited output format (LINE|TYPE|SECRET) to minimise output tokens.
func discoverInChunk(ctx context.Context, filePath, chunkText string,
	lineBase int, cfg Config) ([]DiscoveredSecret, error) {

	prompt := buildDiscoverPrompt(filePath, chunkText, lineBase)
	reqBody, err := json.Marshal(ollamaRequest{
		Model:  cfg.Model,
		Prompt: prompt,
		Stream: true,
		Options: ollamaOptions{NumPredict: 200, Temperature: 0},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, discoverQuickTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		cfg.Host+"/api/generate", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama returned HTTP %d", resp.StatusCode)
	}

	var sb strings.Builder
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var chunk ollamaResponse
		if err := json.Unmarshal(sc.Bytes(), &chunk); err != nil {
			continue
		}
		sb.WriteString(chunk.Response)
		if chunk.Done {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading stream: %w", err)
	}

	return parseDiscoverResponse(sb.String(), chunkText, lineBase), nil
}

// buildDiscoverPrompt asks the LLM to output findings as compact LINE|TYPE|SECRET
// lines, minimising output tokens for fast inference.
func buildDiscoverPrompt(filePath, content string, lineBase int) string {
	return fmt.Sprintf(`Security scan. Find secrets in these lines from %s (starting at line %d).

%s

Output one finding per line in this exact format: LINE|TYPE|SECRET
Types: password, api_key, private_key, token, hash
SECRET must be the actual value, not the key name.
If no secrets: output NONE
No explanations.`, filePath, lineBase, content)
}

// parseDiscoverResponse converts the compact LINE|TYPE|SECRET response into
// []DiscoveredSecret.  Lines that don't match the format are ignored.
// Duplicate (line, secret) pairs within the same response are deduplicated.
func parseDiscoverResponse(raw, chunkText string, lineBase int) []DiscoveredSecret {
	chunkLines := strings.Split(chunkText, "\n")
	seen := make(map[string]struct{})
	var results []DiscoveredSecret
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.EqualFold(line, "none") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			continue
		}
		lineNum, err := parseInt(parts[0])
		if err != nil || lineNum < 1 {
			continue
		}
		secretVal := strings.TrimSpace(parts[2])
		if secretVal == "" {
			continue
		}
		dupKey := fmt.Sprintf("%d:%s", lineNum, strings.ToLower(secretVal))
		if _, dup := seen[dupKey]; dup {
			continue
		}
		seen[dupKey] = struct{}{}

		contextLine := ""
		chunkIdx := lineNum - lineBase
		if chunkIdx >= 0 && chunkIdx < len(chunkLines) {
			contextLine = chunkLines[chunkIdx]
		}
		results = append(results, DiscoveredSecret{
			Line:       lineNum,
			Secret:     secretVal,
			Type:       strings.TrimSpace(parts[1]),
			Confidence: 0.85, // fixed confidence; verify pass will re-evaluate
			Context:    contextLine,
		})
	}
	return results
}

// parseInt parses a trimmed integer string.
func parseInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not an int: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	if len(s) == 0 {
		return 0, fmt.Errorf("empty")
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func existingKey(file string, line int, secret string) string {
	return fmt.Sprintf("%s:%d:%s", file, line, secret)
}

func fingerprintDiscover(file string, line int, secret string) string {
	h := uint32(2166136261)
	for _, b := range []byte(secret) {
		h ^= uint32(b)
		h *= 16777619
	}
	return fmt.Sprintf("%s:llm-discovered:%d:%08x", file, line, h)
}

// shannonEntropyF32 computes Shannon entropy as float32 to match report.Finding.Entropy.
func shannonEntropyF32(s string) float32 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int, 64)
	for _, r := range s {
		counts[r]++
	}
	inv := 1.0 / float64(len(s))
	var h float64
	for _, c := range counts {
		p := float64(c) * inv
		h -= p * math.Log2(p)
	}
	return float32(h)
}

func writeDiscoverAudit(f *os.File, entry DiscoverAuditEntry) {
	if f == nil {
		return
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = f.Write(append(line, '\n'))
}
