// Package llm provides an optional post-scan false-positive reduction layer
// that sends findings to a locally hosted LLM (via Ollama) for triage.
// It is off by default and activated with --llm-verify.
package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
)

// verdictFieldRe / confFieldRe are used as a fallback when the LLM produces
// malformed JSON (e.g. unescaped quotes or stray braces in the reasoning field).
// They extract only the fields that matter for filtering — reasoning is ignored.
var (
	verdictFieldRe = regexp.MustCompile(`"verdict"\s*:\s*"([A-Z_]+)"`)
	confFieldRe    = regexp.MustCompile(`"confidence"\s*:\s*([0-9]*\.?[0-9]+)`)
)

const (
	DefaultModel   = "llama3"
	DefaultHost    = "http://localhost:11434"
	AuditLogFile   = "llm_audit.jsonl"
	defaultTimeout = 60 * time.Second
)

// Config holds the LLM configuration shared by discovery and verification.
type Config struct {
	Model          string
	Host           string
	MinConf        float64 // minimum confidence to act on a FALSE_POSITIVE verdict (default 0.75)
	Workers        int     // concurrent workers for discovery (0 = use DefaultDiscoverWorkers)
	EntropyMinLen  int     // minimum token length for entropy check (0 = use entropyMinLen default)
}

// Verdict is the JSON response from the LLM.
type Verdict struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning"`
}

// AuditEntry is one line written to llm_audit.jsonl.
type AuditEntry struct {
	Timestamp   string  `json:"timestamp"`
	File        string  `json:"file"`
	Line        int     `json:"line"`
	RuleID      string  `json:"rule_id"`
	Entropy     float32 `json:"entropy"`
	Verdict     string  `json:"verdict"`
	Confidence  float64 `json:"confidence"`
	Reasoning   string  `json:"reasoning"`
	Fingerprint string  `json:"fingerprint"`
}

// ollamaOptions tunes generation parameters to keep responses fast and focused.
type ollamaOptions struct {
	NumPredict  int     `json:"num_predict"`  // max tokens to generate
	Temperature float64 `json:"temperature"`  // 0 = deterministic
}

// ollamaRequest is the payload sent to the Ollama /api/generate endpoint.
type ollamaRequest struct {
	Model   string        `json:"model"`
	Prompt  string        `json:"prompt"`
	Stream  bool          `json:"stream"`
	Options ollamaOptions `json:"options"`
}

// ollamaResponse captures relevant fields from Ollama's streaming JSON lines.
type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// FilterFalsePositives calls the local LLM for each finding and removes those
// classified as FALSE_POSITIVE with confidence >= cfg.MinConf.
// If Ollama is unreachable, it logs a warning and returns all findings unfiltered.
func FilterFalsePositives(ctx context.Context, findings []report.Finding, cfg Config) []report.Finding {
	if len(findings) == 0 {
		return findings
	}

	// Set defaults.
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	if cfg.Host == "" {
		cfg.Host = DefaultHost
	}
	if cfg.MinConf == 0 {
		cfg.MinConf = 0.75
	}

	// Check Ollama connectivity.
	if !ping(ctx, cfg.Host) {
		logging.Warn().
			Str("host", cfg.Host).
			Msg("LLM verify: Ollama is unreachable, returning all findings unfiltered")
		return findings
	}

	// Open audit log.
	auditFile, err := os.OpenFile(AuditLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		logging.Warn().Err(err).Msgf("LLM verify: could not open audit log %s, audit logging disabled", AuditLogFile)
		auditFile = nil
	}
	if auditFile != nil {
		defer func() { _ = auditFile.Close() }()
	}

	kept := make([]report.Finding, 0, len(findings))
	for _, f := range findings {
		verdict, err := classify(ctx, f, cfg)
		if err != nil {
			logging.Warn().Err(err).Str("fingerprint", f.Fingerprint).
				Msg("LLM verify: classification failed, keeping finding")
			kept = append(kept, f)
			continue
		}

		writeAudit(auditFile, f, verdict)

		if strings.EqualFold(verdict.Verdict, "FALSE_POSITIVE") && verdict.Confidence >= cfg.MinConf {
			logging.Debug().
				Str("file", f.File).
				Int("line", f.StartLine).
				Str("rule", f.RuleID).
				Float64("confidence", verdict.Confidence).
				Msg("LLM verify: filtered false positive")
			continue
		}
		kept = append(kept, f)
	}

	filtered := len(findings) - len(kept)
	if filtered > 0 {
		logging.Info().
			Int("filtered", filtered).
			Int("remaining", len(kept)).
			Str("audit_log", AuditLogFile).
			Msg("LLM verify: false positives removed")
	}

	return kept
}

// verifyContextLines is the number of lines above and below a finding to
// include in the verification prompt, giving the LLM richer context.
const verifyContextLines = 5

// readFileContext reads up to n lines before and after lineNum from path.
// Returns an empty string if the file cannot be read.
func readFileContext(path string, lineNum int, n int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	start := lineNum - 1 - n
	if start < 0 {
		start = 0
	}
	end := lineNum + n // exclusive, 0-based
	if end > len(lines) {
		end = len(lines)
	}
	var sb strings.Builder
	for i := start; i < end; i++ {
		lineNo := i + 1
		if lineNo == lineNum {
			sb.WriteString(fmt.Sprintf(">>> %d: %s\n", lineNo, lines[i]))
		} else {
			sb.WriteString(fmt.Sprintf("    %d: %s\n", lineNo, lines[i]))
		}
	}
	return sb.String()
}

// classify sends a single finding to the LLM and parses the verdict.
func classify(ctx context.Context, f report.Finding, cfg Config) (*Verdict, error) {
	fileCtx := readFileContext(f.File, f.StartLine, verifyContextLines)
	prompt := buildPrompt(f, fileCtx)

	reqBody, err := json.Marshal(ollamaRequest{
		Model:  cfg.Model,
		Prompt: prompt,
		Stream: true,
		Options: ollamaOptions{NumPredict: 256, Temperature: 0},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	resp, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		cfg.Host+"/api/generate", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	httpResp, err := client.Do(resp)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4096))
		return nil, fmt.Errorf("ollama returned HTTP %d: %s", httpResp.StatusCode, body)
	}

	// Ollama streams one JSON object per line; accumulate the response text.
	var sb strings.Builder
	scanner := bufio.NewScanner(httpResp.Body)
	for scanner.Scan() {
		var chunk ollamaResponse
		if err := json.Unmarshal(scanner.Bytes(), &chunk); err != nil {
			continue
		}
		sb.WriteString(chunk.Response)
		if chunk.Done {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading stream: %w", err)
	}

	return parseVerdict(sb.String())
}

// buildPrompt constructs the structured prompt sent to the LLM.
// fileCtx is optional surrounding lines from the source file; pass "" to omit.
func buildPrompt(f report.Finding, fileCtx string) string {
	ctxSection := ""
	if fileCtx != "" {
		ctxSection = fmt.Sprintf("\nSurrounding file context (>>> marks the flagged line):\n%s", fileCtx)
	}
	return fmt.Sprintf(`You are a secret detection expert. Analyze this potential secret finding and determine if it is a TRUE_POSITIVE (real credential/secret) or FALSE_POSITIVE (test data, placeholder, example value, commented-out code, etc).

Finding:
File: %s
Line %d: %s
Rule matched: %s
Entropy score: %.4f%s

Respond with JSON only: {"verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE", "confidence": 0.0-1.0, "reasoning": "..."}`,
		f.File,
		f.StartLine,
		strings.TrimSpace(f.Line),
		f.RuleID,
		f.Entropy,
		ctxSection,
	)
}

// parseVerdict extracts the JSON verdict from the LLM's free-form response.
//
// Strategy:
//  1. Scan forward from the first '{' tracking string/brace depth to find the
//     true closing '}', avoiding the LastIndex pitfall where a stray '}' inside
//     a string value is mistaken for the object boundary.
//  2. If json.Unmarshal still fails (e.g. unescaped quotes embedded in the
//     reasoning text), fall back to regex extraction of just verdict+confidence.
//     The reasoning field is not used for filtering so loss is acceptable.
func parseVerdict(raw string) (*Verdict, error) {
	start := strings.Index(raw, "{")
	if start == -1 {
		return nil, fmt.Errorf("no JSON object found in LLM response: %q", raw)
	}

	// Walk forward tracking depth and string state to find the matching '}'.
	end := -1
	depth, inStr, escaped := 0, false, false
	for i := start; i < len(raw); i++ {
		c := raw[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && inStr {
			escaped = true
			continue
		}
		if c == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end != -1 {
			break
		}
	}
	// Attempt structured parse if we found a balanced object.
	// On any failure — unmatched braces, malformed interior, empty verdict —
	// fall through to the regex fallback below.
	var v Verdict
	if end != -1 {
		if err := json.Unmarshal([]byte(raw[start:end+1]), &v); err == nil && v.Verdict != "" {
			return &v, nil
		}
	}

	// Fallback: the LLM generated malformed JSON (typically unescaped quotes or
	// stray braces in the reasoning field).  Extract only the fields that matter
	// for filtering — the reasoning text is never used downstream.
	vm := verdictFieldRe.FindStringSubmatch(raw)
	if vm == nil {
		return nil, fmt.Errorf("could not parse verdict from LLM response: %q", raw)
	}
	v.Verdict = vm[1]
	if cm := confFieldRe.FindStringSubmatch(raw); cm != nil {
		_, _ = fmt.Sscanf(cm[1], "%f", &v.Confidence)
	}
	return &v, nil
}

// ping checks whether the Ollama server is reachable.
func ping(ctx context.Context, host string) bool {
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(pingCtx, http.MethodGet, host, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// writeAudit appends one JSON line to the audit file.
func writeAudit(f *os.File, finding report.Finding, v *Verdict) {
	if f == nil {
		return
	}
	entry := AuditEntry{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		File:        finding.File,
		Line:        finding.StartLine,
		RuleID:      finding.RuleID,
		Entropy:     finding.Entropy,
		Verdict:     v.Verdict,
		Confidence:  v.Confidence,
		Reasoning:   v.Reasoning,
		Fingerprint: finding.Fingerprint,
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = f.Write(append(line, '\n'))
}
