// Package parser provides ModSecurity JSON audit log parsing.
package parser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// modsecTimestampLayout is the time format used by ModSecurity audit logs.
// ModSecurity uses ctime(3) format where single-digit days are space-padded.
// Go's _2 verb matches a space-padded day field (e.g. " 6" for day 6, "15" for day 15).
// Example: "Sun Apr  6 10:23:45 2026"
const modsecTimestampLayout = "Mon Jan _2 15:04:05 2006"

// transactionPrefix is the JSON prefix that identifies a ModSecurity audit log line.
const transactionPrefix = `{"transaction"`

// Severity levels emitted by ModSecurity CRS rules.
const (
	SeverityCritical = "CRITICAL"
	SeverityWarning  = "WARNING"
	SeverityNotice   = "NOTICE"
)

// Event represents a single parsed ModSecurity WAF event.
type Event struct {
	Time     time.Time
	ClientIP string
	Method   string
	URI      string
	HTTPCode int
	Rules    []RuleMatch
}

// RuleMatch holds details of a single CRS rule that fired.
type RuleMatch struct {
	RuleID   string
	Message  string
	Severity string
	Data     string
}

// transaction is the intermediate struct matching the ModSecurity JSON Serial format.
type transaction struct {
	Transaction struct {
		ClientIP  string `json:"client_ip"`
		TimeStamp string `json:"time_stamp"`
		Request   struct {
			Method  string            `json:"method"`
			URI     string            `json:"uri"`
			Headers map[string]string `json:"headers"`
		} `json:"request"`
		Response struct {
			HTTPCode int `json:"http_code"`
		} `json:"response"`
		Messages []struct {
			Message string `json:"message"`
			Details struct {
				RuleID   string `json:"ruleId"`
				Severity string `json:"severity"`
				Data     string `json:"data"`
			} `json:"details"`
		} `json:"messages"`
	} `json:"transaction"`
}

// ParseLine parses a single JSON line from the ModSecurity audit log into an Event.
// Lines that do not start with {"transaction" are rejected.
// Events with empty messages (no rules triggered) are still returned — they represent
// logged transactions in DetectionOnly mode or pass-throughs worth monitoring.
func ParseLine(line string) (*Event, error) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, transactionPrefix) {
		return nil, fmt.Errorf("not a transaction line")
	}

	var tx transaction
	if err := json.Unmarshal([]byte(trimmed), &tx); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %w", err)
	}

	t := tx.Transaction

	ts, err := time.Parse(modsecTimestampLayout, t.TimeStamp)
	if err != nil {
		return nil, fmt.Errorf("time parse failed: %w", err)
	}

	// IP resolution: X-Real-Ip header takes priority over client_ip.
	clientIP := t.ClientIP
	if realIP, ok := t.Request.Headers["X-Real-Ip"]; ok && realIP != "" {
		clientIP = realIP
	}

	rules := make([]RuleMatch, 0, len(t.Messages))
	for _, msg := range t.Messages {
		rules = append(rules, RuleMatch{
			RuleID:   msg.Details.RuleID,
			Message:  msg.Message,
			Severity: msg.Details.Severity,
			Data:     msg.Details.Data,
		})
	}

	return &Event{
		Time:     ts,
		ClientIP: clientIP,
		Method:   t.Request.Method,
		URI:      t.Request.URI,
		HTTPCode: t.Response.HTTPCode,
		Rules:    rules,
	}, nil
}

// ParseStream reads lines from r, parses each as a ModSecurity audit log entry,
// and sends successfully parsed events to ch. Unparseable lines are skipped silently.
// The function closes ch when the reader is exhausted.
func ParseStream(r io.Reader, ch chan<- *Event) {
	defer close(ch)

	scanner := bufio.NewScanner(r)

	// ModSecurity JSON lines can be large (request bodies included); use 4 MB.
	// scanner.Err() is intentionally not propagated — the caller detects
	// stream closure via the closed channel.
	const maxLineSize = 4 << 20 // 4 MB
	scanner.Buffer(make([]byte, 0, maxLineSize), maxLineSize)

	for scanner.Scan() {
		ev, err := ParseLine(scanner.Text())
		if err != nil {
			continue
		}
		ch <- ev
	}
}
