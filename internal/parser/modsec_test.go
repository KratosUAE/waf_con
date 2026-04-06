package parser

import (
	"strings"
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantErr  bool
		checkEvt func(t *testing.T, ev *Event)
	}{
		{
			name: "valid event with X-Real-Ip",
			line: `{"transaction":{"client_ip":"1.2.3.4","time_stamp":"Sun Apr  6 10:23:45 2026","request":{"method":"GET","uri":"/v1/models?id=1 UNION SELECT","headers":{"X-Real-Ip":"5.6.7.8","User-Agent":"nikto","Host":"llm.xpanceo.com"}},"response":{"http_code":403},"messages":[{"message":"SQL Injection Attack","details":{"ruleId":"942100","severity":"CRITICAL","data":"Matched Data: 1 UNION SELECT"}}]}}`,
			wantErr: false,
			checkEvt: func(t *testing.T, ev *Event) {
				t.Helper()
				if ev.ClientIP != "5.6.7.8" {
					t.Errorf("ClientIP = %q, want %q", ev.ClientIP, "5.6.7.8")
				}
				if ev.Method != "GET" {
					t.Errorf("Method = %q, want %q", ev.Method, "GET")
				}
				if ev.URI != "/v1/models?id=1 UNION SELECT" {
					t.Errorf("URI = %q, want %q", ev.URI, "/v1/models?id=1 UNION SELECT")
				}
				if ev.HTTPCode != 403 {
					t.Errorf("HTTPCode = %d, want %d", ev.HTTPCode, 403)
				}
				wantTime := time.Date(2026, time.April, 6, 10, 23, 45, 0, time.UTC)
				if !ev.Time.Equal(wantTime) {
					t.Errorf("Time = %v, want %v", ev.Time, wantTime)
				}
				if len(ev.Rules) != 1 {
					t.Fatalf("len(Rules) = %d, want 1", len(ev.Rules))
				}
				r := ev.Rules[0]
				if r.RuleID != "942100" {
					t.Errorf("RuleID = %q, want %q", r.RuleID, "942100")
				}
				if r.Severity != "CRITICAL" {
					t.Errorf("Severity = %q, want %q", r.Severity, "CRITICAL")
				}
				if r.Message != "SQL Injection Attack" {
					t.Errorf("Message = %q, want %q", r.Message, "SQL Injection Attack")
				}
			},
		},
		{
			name: "fallback to client_ip when no X-Real-Ip",
			line: `{"transaction":{"client_ip":"10.0.0.1","time_stamp":"Mon Jan  2 15:04:05 2006","request":{"method":"POST","uri":"/api","headers":{"Host":"example.com"}},"response":{"http_code":403},"messages":[{"message":"Test Rule","details":{"ruleId":"900001","severity":"WARNING","data":"test"}}]}}`,
			wantErr: false,
			checkEvt: func(t *testing.T, ev *Event) {
				t.Helper()
				if ev.ClientIP != "10.0.0.1" {
					t.Errorf("ClientIP = %q, want %q (fallback)", ev.ClientIP, "10.0.0.1")
				}
				if ev.Method != "POST" {
					t.Errorf("Method = %q, want %q", ev.Method, "POST")
				}
			},
		},
		{
			name: "multiple rules",
			line: `{"transaction":{"client_ip":"1.1.1.1","time_stamp":"Mon Jan  2 15:04:05 2006","request":{"method":"GET","uri":"/test","headers":{}},"response":{"http_code":403},"messages":[{"message":"Rule A","details":{"ruleId":"100","severity":"CRITICAL","data":"a"}},{"message":"Rule B","details":{"ruleId":"200","severity":"WARNING","data":"b"}}]}}`,
			wantErr: false,
			checkEvt: func(t *testing.T, ev *Event) {
				t.Helper()
				if len(ev.Rules) != 2 {
					t.Fatalf("len(Rules) = %d, want 2", len(ev.Rules))
				}
				if ev.Rules[0].RuleID != "100" {
					t.Errorf("Rules[0].RuleID = %q, want %q", ev.Rules[0].RuleID, "100")
				}
				if ev.Rules[1].RuleID != "200" {
					t.Errorf("Rules[1].RuleID = %q, want %q", ev.Rules[1].RuleID, "200")
				}
			},
		},
		{
			name:    "empty messages array still parsed",
			line:    `{"transaction":{"client_ip":"1.2.3.4","time_stamp":"Mon Jan  2 15:04:05 2006","request":{"method":"GET","uri":"/ok","headers":{}},"response":{"http_code":200},"messages":[]}}`,
			wantErr: false,
			checkEvt: func(t *testing.T, ev *Event) {
				t.Helper()
				if ev.ClientIP != "1.2.3.4" {
					t.Errorf("ClientIP = %q, want %q", ev.ClientIP, "1.2.3.4")
				}
				if len(ev.Rules) != 0 {
					t.Errorf("len(Rules) = %d, want 0", len(ev.Rules))
				}
				if ev.HTTPCode != 200 {
					t.Errorf("HTTPCode = %d, want 200", ev.HTTPCode)
				}
			},
		},
		{
			name:    "not a transaction line",
			line:    `some random log line`,
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			line:    `{"transaction": broken}`,
			wantErr: true,
		},
		{
			name:    "empty line",
			line:    "",
			wantErr: true,
		},
		{
			name:    "whitespace-only line",
			line:    "   ",
			wantErr: true,
		},
		{
			name: "double-digit day (day 15) parsed correctly",
			line: `{"transaction":{"client_ip":"1.1.1.1","time_stamp":"Mon Jan 15 12:00:00 2024","request":{"method":"GET","uri":"/","headers":{}},"response":{"http_code":403},"messages":[{"message":"Test","details":{"ruleId":"100","severity":"NOTICE","data":"d"}}]}}`,
			wantErr: false,
			checkEvt: func(t *testing.T, ev *Event) {
				t.Helper()
				wantTime := time.Date(2024, time.January, 15, 12, 0, 0, 0, time.UTC)
				if !ev.Time.Equal(wantTime) {
					t.Errorf("Time = %v, want %v (double-digit day)", ev.Time, wantTime)
				}
			},
		},
		{
			name: "line with leading whitespace is accepted",
			line: `  {"transaction":{"client_ip":"1.1.1.1","time_stamp":"Mon Jan  2 15:04:05 2006","request":{"method":"GET","uri":"/ws","headers":{}},"response":{"http_code":403},"messages":[{"message":"M","details":{"ruleId":"1","severity":"NOTICE","data":"d"}}]}}`,
			wantErr: false,
			checkEvt: func(t *testing.T, ev *Event) {
				t.Helper()
				if ev.HTTPCode != 403 {
					t.Errorf("HTTPCode = %d, want 403", ev.HTTPCode)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := ParseLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ev == nil {
				t.Fatal("expected event, got nil")
			}
			if tt.checkEvt != nil {
				tt.checkEvt(t, ev)
			}
		})
	}
}

func TestParseStream(t *testing.T) {
	input := strings.Join([]string{
		`some noise line`,
		`{"transaction":{"client_ip":"1.1.1.1","time_stamp":"Mon Jan  2 15:04:05 2006","request":{"method":"GET","uri":"/a","headers":{}},"response":{"http_code":403},"messages":[{"message":"A","details":{"ruleId":"1","severity":"CRITICAL","data":"x"}}]}}`,
		`malformed json {{{`,
		`{"transaction":{"client_ip":"2.2.2.2","time_stamp":"Mon Jan  2 15:04:05 2006","request":{"method":"POST","uri":"/b","headers":{"X-Real-Ip":"3.3.3.3"}},"response":{"http_code":403},"messages":[{"message":"B","details":{"ruleId":"2","severity":"WARNING","data":"y"}}]}}`,
		`{"transaction":{"client_ip":"4.4.4.4","time_stamp":"Mon Jan  2 15:04:05 2006","request":{"method":"DELETE","uri":"/c","headers":{}},"response":{"http_code":200},"messages":[]}}`,
	}, "\n")

	// ParseStream closes ch when the reader is exhausted.
	ch := make(chan *Event, 10)
	go ParseStream(strings.NewReader(input), ch)

	var events []*Event
	for ev := range ch {
		events = append(events, ev)
	}

	// 3 events: valid with rules, valid with X-Real-Ip, valid with empty messages.
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	if events[0].ClientIP != "1.1.1.1" {
		t.Errorf("events[0].ClientIP = %q, want %q", events[0].ClientIP, "1.1.1.1")
	}
	if events[0].URI != "/a" {
		t.Errorf("events[0].URI = %q, want %q", events[0].URI, "/a")
	}

	// Second event should use X-Real-Ip.
	if events[1].ClientIP != "3.3.3.3" {
		t.Errorf("events[1].ClientIP = %q, want %q (from X-Real-Ip)", events[1].ClientIP, "3.3.3.3")
	}
	if events[1].Method != "POST" {
		t.Errorf("events[1].Method = %q, want %q", events[1].Method, "POST")
	}

	// Third event has empty messages but is still parsed.
	if events[2].ClientIP != "4.4.4.4" {
		t.Errorf("events[2].ClientIP = %q, want %q", events[2].ClientIP, "4.4.4.4")
	}
	if len(events[2].Rules) != 0 {
		t.Errorf("events[2] should have 0 rules, got %d", len(events[2].Rules))
	}
}

func TestParseStream_EmptyReader(t *testing.T) {
	// ParseStream closes ch when the reader is exhausted.
	ch := make(chan *Event, 10)
	go ParseStream(strings.NewReader(""), ch)

	var count int
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 events from empty reader, got %d", count)
	}
}
