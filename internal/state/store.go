// Package state provides in-memory storage for WAF events and aggregates.
// All mutations happen in Bubble Tea's single Update() goroutine, so no mutex is needed.
package state

import (
	"sort"
	"time"

	"waf_con/internal/parser"
)

// defaultCapacity is the ring buffer size for events.
const defaultCapacity = 5000

// secondsPerMinute is the number of seconds in one minute, used for bucket keying.
const secondsPerMinute = 60

// sparklineMinutes is the number of minute buckets kept for sparkline display.
const sparklineMinutes = 30

// IPStat holds aggregated statistics for a single source IP.
type IPStat struct {
	IP       string
	Count    int
	LastSeen time.Time
	Geo      string
}

// RuleStat holds aggregated statistics for a single ModSecurity rule.
type RuleStat struct {
	RuleID      string
	Count       int
	Description string
	Severity    string
}

// Store is the central in-memory state container for WAF events and aggregates.
// It is NOT safe for concurrent use — callers must ensure single-goroutine access
// (enforced by Bubble Tea's Update() loop).
type Store struct {
	// Ring buffer.
	events   []*parser.Event
	head     int
	count    int
	capacity int

	// Aggregate counters (survive ring buffer eviction).
	ipCounts  map[string]int
	ruleCounts map[string]int

	// Metadata.
	ipLastSeen  map[string]time.Time
	ipGeo       map[string]string
	ruleDesc    map[string]string
	ruleSeverity map[string]string

	// False positive candidates: rules that triggered on HTTP 2xx responses.
	fpRuleCounts map[string]int

	// Sparkline: keyed by unix_timestamp / 60.
	minuteBuckets map[int64]int

	totalEvents int
	startedAt   time.Time
}

// NewStore creates a new Store with the default ring buffer capacity of 5000.
func NewStore() *Store {
	return NewStoreWithCapacity(defaultCapacity)
}

// NewStoreWithCapacity creates a new Store with the given ring buffer capacity.
func NewStoreWithCapacity(capacity int) *Store {
	if capacity <= 0 {
		capacity = defaultCapacity
	}
	return &Store{
		events:       make([]*parser.Event, capacity),
		capacity:     capacity,
		ipCounts:     make(map[string]int),
		ruleCounts:   make(map[string]int),
		ipLastSeen:   make(map[string]time.Time),
		ipGeo:        make(map[string]string),
		ruleDesc:     make(map[string]string),
		ruleSeverity: make(map[string]string),
		fpRuleCounts:  make(map[string]int),
		minuteBuckets: make(map[int64]int),
		startedAt:    time.Now(),
	}
}

// Add inserts an event into the ring buffer and updates all counters and aggregates.
func (s *Store) Add(event *parser.Event) {
	if event == nil {
		return
	}

	// Write to ring buffer.
	// s.head is kept in [0, capacity) to prevent unbounded growth.
	idx := s.head
	s.events[idx] = event
	s.head = (s.head + 1) % s.capacity
	if s.count < s.capacity {
		s.count++
	}
	s.totalEvents++

	// IP aggregates.
	s.ipCounts[event.ClientIP]++
	s.ipLastSeen[event.ClientIP] = event.Time

	// Rule aggregates: each rule match in the event counts separately.
	isFP := event.HTTPCode >= 200 && event.HTTPCode < 300 && len(event.Rules) > 0
	for _, rule := range event.Rules {
		s.ruleCounts[rule.RuleID]++
		if _, ok := s.ruleDesc[rule.RuleID]; !ok {
			s.ruleDesc[rule.RuleID] = rule.Message
			s.ruleSeverity[rule.RuleID] = rule.Severity
		}
		if isFP {
			s.fpRuleCounts[rule.RuleID]++
		}
	}

	// Sparkline bucket.
	bucket := event.Time.Unix() / secondsPerMinute
	s.minuteBuckets[bucket]++
}

// Events returns the ring buffer contents with newest first.
// s.head is in [0, capacity), so the minimum of (s.head - 1 - i) is -capacity;
// adding +s.capacity before the modulo guarantees a non-negative operand.
func (s *Store) Events() []*parser.Event {
	result := make([]*parser.Event, 0, s.count)
	for i := range s.count {
		// Walk backwards from the most recent entry.
		idx := (s.head - 1 - i + s.capacity) % s.capacity
		if s.events[idx] != nil {
			result = append(result, s.events[idx])
		}
	}
	return result
}

// TopIPs returns the top n IPs sorted by hit count descending.
func (s *Store) TopIPs(n int) []IPStat {
	stats := make([]IPStat, 0, len(s.ipCounts))
	for ip, count := range s.ipCounts {
		stats = append(stats, IPStat{
			IP:       ip,
			Count:    count,
			LastSeen: s.ipLastSeen[ip],
			Geo:      s.ipGeo[ip],
		})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Count != stats[j].Count {
			return stats[i].Count > stats[j].Count
		}
		return stats[i].IP < stats[j].IP
	})
	if n > len(stats) {
		n = len(stats)
	}
	return stats[:n]
}

// TopRules returns the top n rules sorted by hit count descending.
func (s *Store) TopRules(n int) []RuleStat {
	stats := make([]RuleStat, 0, len(s.ruleCounts))
	for ruleID, count := range s.ruleCounts {
		stats = append(stats, RuleStat{
			RuleID:      ruleID,
			Count:       count,
			Description: s.ruleDesc[ruleID],
			Severity:    s.ruleSeverity[ruleID],
		})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Count != stats[j].Count {
			return stats[i].Count > stats[j].Count
		}
		return stats[i].RuleID < stats[j].RuleID
	})
	if n > len(stats) {
		n = len(stats)
	}
	return stats[:n]
}

// EventsByIP returns events from the ring buffer matching the given IP, newest first.
func (s *Store) EventsByIP(ip string) []*parser.Event {
	all := s.Events()
	result := make([]*parser.Event, 0)
	for _, ev := range all {
		if ev.ClientIP == ip {
			result = append(result, ev)
		}
	}
	return result
}

// EventsByRule returns events from the ring buffer matching the given rule ID, newest first.
func (s *Store) EventsByRule(ruleID string) []*parser.Event {
	all := s.Events()
	result := make([]*parser.Event, 0)
	for _, ev := range all {
		for _, rule := range ev.Rules {
			if rule.RuleID == ruleID {
				result = append(result, ev)
				break
			}
		}
	}
	return result
}

// FPRules returns rules that triggered on HTTP 2xx responses (false positive candidates),
// sorted by count descending.
func (s *Store) FPRules(n int) []RuleStat {
	stats := make([]RuleStat, 0, len(s.fpRuleCounts))
	for ruleID, count := range s.fpRuleCounts {
		stats = append(stats, RuleStat{
			RuleID:      ruleID,
			Count:       count,
			Description: s.ruleDesc[ruleID],
			Severity:    s.ruleSeverity[ruleID],
		})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Count != stats[j].Count {
			return stats[i].Count > stats[j].Count
		}
		return stats[i].RuleID < stats[j].RuleID
	})
	if n > len(stats) {
		n = len(stats)
	}
	return stats[:n]
}

// FPEventsByRule returns events from the ring buffer where HTTP 2xx and the rule triggered.
func (s *Store) FPEventsByRule(ruleID string) []*parser.Event {
	all := s.Events()
	result := make([]*parser.Event, 0)
	for _, ev := range all {
		if ev.HTTPCode < 200 || ev.HTTPCode >= 300 {
			continue
		}
		for _, rule := range ev.Rules {
			if rule.RuleID == ruleID {
				result = append(result, ev)
				break
			}
		}
	}
	return result
}

// TotalEvents returns the lifetime event count (not limited by ring buffer).
func (s *Store) TotalEvents() int {
	return s.totalEvents
}

// EventsPerMinute returns the average events per minute since the store was created.
func (s *Store) EventsPerMinute() float64 {
	elapsed := time.Since(s.startedAt).Minutes()
	if elapsed < 1 {
		elapsed = 1
	}
	return float64(s.totalEvents) / elapsed
}

// Sparkline returns event counts for the last 30 minutes, one bucket per minute.
// Index 0 is the oldest minute, index 29 is the current minute.
func (s *Store) Sparkline() [sparklineMinutes]int {
	var result [sparklineMinutes]int
	now := time.Now().Unix() / secondsPerMinute
	for i := range sparklineMinutes {
		bucket := now - int64(sparklineMinutes-1-i)
		result[i] = s.minuteBuckets[bucket]
	}
	return result
}

// UniqueIPs returns the number of distinct source IPs seen.
func (s *Store) UniqueIPs() int {
	return len(s.ipCounts)
}

// UniqueRules returns the number of distinct rules that have fired.
func (s *Store) UniqueRules() int {
	return len(s.ruleCounts)
}

// SetGeo sets the geographic location string for an IP address.
// Called when async geo lookup completes.
func (s *Store) SetGeo(ip, geo string) {
	s.ipGeo[ip] = geo
}

// CleanOldBuckets removes sparkline minute buckets older than 30 minutes.
// Should be called periodically to prevent unbounded map growth.
func (s *Store) CleanOldBuckets() {
	cutoff := time.Now().Unix()/secondsPerMinute - sparklineMinutes
	for bucket := range s.minuteBuckets {
		if bucket < cutoff {
			delete(s.minuteBuckets, bucket)
		}
	}
}
