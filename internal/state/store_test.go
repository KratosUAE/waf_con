package state

import (
	"testing"
	"time"

	"waf_con/internal/parser"
)

func makeEvent(ip, method, uri string, ruleID, msg, severity string, ts time.Time) *parser.Event {
	return &parser.Event{
		Time:     ts,
		ClientIP: ip,
		Method:   method,
		URI:      uri,
		HTTPCode: 403,
		Rules: []parser.RuleMatch{
			{RuleID: ruleID, Message: msg, Severity: severity},
		},
	}
}

func TestNewStore(t *testing.T) {
	s := NewStore()
	if s.TotalEvents() != 0 {
		t.Errorf("expected 0 total events, got %d", s.TotalEvents())
	}
	if s.UniqueIPs() != 0 {
		t.Errorf("expected 0 unique IPs, got %d", s.UniqueIPs())
	}
	if s.UniqueRules() != 0 {
		t.Errorf("expected 0 unique rules, got %d", s.UniqueRules())
	}
}

func TestAdd_UpdatesCounters(t *testing.T) {
	s := NewStore()
	now := time.Now()

	ev := makeEvent("1.2.3.4", "GET", "/test", "942100", "SQL Injection", "CRITICAL", now)
	s.Add(ev)

	if s.TotalEvents() != 1 {
		t.Errorf("expected 1 total event, got %d", s.TotalEvents())
	}
	if s.UniqueIPs() != 1 {
		t.Errorf("expected 1 unique IP, got %d", s.UniqueIPs())
	}
	if s.UniqueRules() != 1 {
		t.Errorf("expected 1 unique rule, got %d", s.UniqueRules())
	}
}

func TestAdd_NilEvent(t *testing.T) {
	s := NewStore()
	s.Add(nil) // should not panic
	if s.TotalEvents() != 0 {
		t.Errorf("expected 0 total events after nil add, got %d", s.TotalEvents())
	}
}

func TestEvents_NewestFirst(t *testing.T) {
	s := NewStoreWithCapacity(10)
	now := time.Now()

	s.Add(makeEvent("1.1.1.1", "GET", "/a", "100", "m", "NOTICE", now))
	s.Add(makeEvent("2.2.2.2", "POST", "/b", "200", "m", "CRITICAL", now.Add(time.Second)))
	s.Add(makeEvent("3.3.3.3", "PUT", "/c", "300", "m", "WARNING", now.Add(2*time.Second)))

	events := s.Events()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].ClientIP != "3.3.3.3" {
		t.Errorf("expected newest first (3.3.3.3), got %s", events[0].ClientIP)
	}
	if events[2].ClientIP != "1.1.1.1" {
		t.Errorf("expected oldest last (1.1.1.1), got %s", events[2].ClientIP)
	}
}

func TestRingBuffer_Wrap(t *testing.T) {
	const capacity = 3
	s := NewStoreWithCapacity(capacity)
	now := time.Now()

	// Add 5 events to a buffer of size 3.
	for i := range 5 {
		s.Add(makeEvent("1.1.1.1", "GET", "/", "100", "m", "NOTICE", now.Add(time.Duration(i)*time.Second)))
	}

	if s.TotalEvents() != 5 {
		t.Errorf("expected 5 total events, got %d", s.TotalEvents())
	}

	events := s.Events()
	if len(events) != capacity {
		t.Errorf("expected %d events in ring buffer, got %d", capacity, len(events))
	}
}

func TestRingBuffer_CountersSurviveEviction(t *testing.T) {
	s := NewStoreWithCapacity(2)
	now := time.Now()

	s.Add(makeEvent("1.1.1.1", "GET", "/", "100", "m", "NOTICE", now))
	s.Add(makeEvent("2.2.2.2", "GET", "/", "200", "m", "CRITICAL", now))
	s.Add(makeEvent("3.3.3.3", "GET", "/", "300", "m", "WARNING", now))

	// Ring buffer should only have 2 events, but IP/rule counters survive.
	if s.UniqueIPs() != 3 {
		t.Errorf("expected 3 unique IPs (counters survive eviction), got %d", s.UniqueIPs())
	}
	if s.UniqueRules() != 3 {
		t.Errorf("expected 3 unique rules, got %d", s.UniqueRules())
	}
}

func TestTopIPs(t *testing.T) {
	s := NewStore()
	now := time.Now()

	// IP "1.1.1.1" has 3 hits, "2.2.2.2" has 1 hit.
	for range 3 {
		s.Add(makeEvent("1.1.1.1", "GET", "/", "100", "m", "NOTICE", now))
	}
	s.Add(makeEvent("2.2.2.2", "GET", "/", "100", "m", "NOTICE", now))

	top := s.TopIPs(1)
	if len(top) != 1 {
		t.Fatalf("expected 1 top IP, got %d", len(top))
	}
	if top[0].IP != "1.1.1.1" {
		t.Errorf("expected top IP 1.1.1.1, got %s", top[0].IP)
	}
	if top[0].Count != 3 {
		t.Errorf("expected count 3, got %d", top[0].Count)
	}
}

func TestTopIPs_RequestMoreThanExist(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Add(makeEvent("1.1.1.1", "GET", "/", "100", "m", "NOTICE", now))

	top := s.TopIPs(10)
	if len(top) != 1 {
		t.Errorf("expected 1 IP when requesting 10, got %d", len(top))
	}
}

func TestTopRules(t *testing.T) {
	s := NewStore()
	now := time.Now()

	// Rule 942100 fires 3 times (across events), rule 941100 fires 1 time.
	for range 3 {
		s.Add(makeEvent("1.1.1.1", "GET", "/", "942100", "SQL Injection", "CRITICAL", now))
	}
	s.Add(makeEvent("2.2.2.2", "GET", "/", "941100", "XSS", "WARNING", now))

	top := s.TopRules(2)
	if len(top) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(top))
	}
	if top[0].RuleID != "942100" {
		t.Errorf("expected top rule 942100, got %s", top[0].RuleID)
	}
	if top[0].Count != 3 {
		t.Errorf("expected count 3, got %d", top[0].Count)
	}
	if top[0].Description != "SQL Injection" {
		t.Errorf("expected description 'SQL Injection', got %s", top[0].Description)
	}
	if top[0].Severity != "CRITICAL" {
		t.Errorf("expected severity CRITICAL, got %s", top[0].Severity)
	}
}

func TestEventsByIP(t *testing.T) {
	s := NewStoreWithCapacity(10)
	now := time.Now()

	s.Add(makeEvent("1.1.1.1", "GET", "/a", "100", "m", "NOTICE", now))
	s.Add(makeEvent("2.2.2.2", "GET", "/b", "100", "m", "NOTICE", now))
	s.Add(makeEvent("1.1.1.1", "POST", "/c", "200", "m", "CRITICAL", now))

	filtered := s.EventsByIP("1.1.1.1")
	if len(filtered) != 2 {
		t.Errorf("expected 2 events for 1.1.1.1, got %d", len(filtered))
	}
}

func TestEventsByIP_NotFound(t *testing.T) {
	s := NewStore()
	filtered := s.EventsByIP("9.9.9.9")
	if len(filtered) != 0 {
		t.Errorf("expected 0 events for unknown IP, got %d", len(filtered))
	}
}

func TestEventsByRule(t *testing.T) {
	s := NewStoreWithCapacity(10)
	now := time.Now()

	s.Add(makeEvent("1.1.1.1", "GET", "/", "942100", "SQL", "CRITICAL", now))
	s.Add(makeEvent("2.2.2.2", "GET", "/", "941100", "XSS", "WARNING", now))
	s.Add(makeEvent("3.3.3.3", "GET", "/", "942100", "SQL", "CRITICAL", now))

	filtered := s.EventsByRule("942100")
	if len(filtered) != 2 {
		t.Errorf("expected 2 events for rule 942100, got %d", len(filtered))
	}
}

func TestSetGeo(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Add(makeEvent("1.1.1.1", "GET", "/", "100", "m", "NOTICE", now))

	s.SetGeo("1.1.1.1", "US, New York")

	top := s.TopIPs(1)
	if top[0].Geo != "US, New York" {
		t.Errorf("expected geo 'US, New York', got '%s'", top[0].Geo)
	}
}

func TestSparkline(t *testing.T) {
	s := NewStore()
	now := time.Now()

	// Add events in the current minute.
	s.Add(makeEvent("1.1.1.1", "GET", "/", "100", "m", "NOTICE", now))
	s.Add(makeEvent("1.1.1.1", "GET", "/", "100", "m", "NOTICE", now))

	spark := s.Sparkline()
	// The last bucket (index 29) should have our events.
	if spark[sparklineMinutes-1] != 2 {
		t.Errorf("expected 2 in last sparkline bucket, got %d", spark[sparklineMinutes-1])
	}
	// Earlier buckets should be 0.
	if spark[0] != 0 {
		t.Errorf("expected 0 in first sparkline bucket, got %d", spark[0])
	}
}

func TestEventsPerMinute(t *testing.T) {
	s := NewStore()
	now := time.Now()

	for range 10 {
		s.Add(makeEvent("1.1.1.1", "GET", "/", "100", "m", "NOTICE", now))
	}

	epm := s.EventsPerMinute()
	// With <1 minute elapsed, denominator is clamped to 1.
	if epm != 10.0 {
		t.Errorf("expected 10.0 events/min (clamped), got %f", epm)
	}
}

func TestCleanOldBuckets(t *testing.T) {
	s := NewStore()

	// Insert an event with a timestamp 60 minutes ago.
	oldTime := time.Now().Add(-60 * time.Minute)
	s.Add(makeEvent("1.1.1.1", "GET", "/", "100", "m", "NOTICE", oldTime))

	// Bucket should exist.
	oldBucket := oldTime.Unix() / secondsPerMinute
	if s.minuteBuckets[oldBucket] != 1 {
		t.Fatalf("expected old bucket to have 1, got %d", s.minuteBuckets[oldBucket])
	}

	s.CleanOldBuckets()

	if _, exists := s.minuteBuckets[oldBucket]; exists {
		t.Errorf("expected old bucket to be cleaned up")
	}
}

func TestNewStoreWithCapacity_ZeroDefault(t *testing.T) {
	s := NewStoreWithCapacity(0)
	if s.capacity != defaultCapacity {
		t.Errorf("expected default capacity %d for 0 input, got %d", defaultCapacity, s.capacity)
	}

	s2 := NewStoreWithCapacity(-5)
	if s2.capacity != defaultCapacity {
		t.Errorf("expected default capacity %d for negative input, got %d", defaultCapacity, s2.capacity)
	}
}

func TestMultipleRulesPerEvent(t *testing.T) {
	s := NewStore()
	now := time.Now()

	ev := &parser.Event{
		Time:     now,
		ClientIP: "1.1.1.1",
		Method:   "GET",
		URI:      "/exploit",
		HTTPCode: 403,
		Rules: []parser.RuleMatch{
			{RuleID: "942100", Message: "SQL Injection", Severity: "CRITICAL"},
			{RuleID: "941100", Message: "XSS Attack", Severity: "WARNING"},
		},
	}
	s.Add(ev)

	if s.UniqueRules() != 2 {
		t.Errorf("expected 2 unique rules from single event, got %d", s.UniqueRules())
	}

	top := s.TopRules(2)
	if len(top) != 2 {
		t.Errorf("expected 2 rules, got %d", len(top))
	}
}
