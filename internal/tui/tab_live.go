package tui

import (
	"fmt"
	"strings"

	lipgloss "charm.land/lipgloss/v2"

	"waf_con/internal/parser"
	"waf_con/internal/state"
)

// liveTab renders the live events stream (Tab 1).
type liveTab struct {
	store       *state.Store
	width       int
	height      int
	offset      int  // scroll offset (0 = top, newest)
	autoScroll  bool // auto-scroll to top on new events
	streamEnded bool // set when the Docker log stream is exhausted
}

func newLiveTab(store *state.Store) liveTab {
	return liveTab{
		store:      store,
		autoScroll: true,
	}
}

// update handles key messages for the live tab.
func (t *liveTab) update(key string) {
	switch key {
	case "j", "down":
		events := t.store.Events()
		maxOffset := max(len(events)-t.visibleRows(), 0)
		if t.offset < maxOffset {
			t.offset++
			t.autoScroll = false
		}
	case "k", "up":
		if t.offset > 0 {
			t.offset--
			t.autoScroll = false
		}
		if t.offset == 0 {
			t.autoScroll = true
		}
	case "home":
		t.offset = 0
		t.autoScroll = true
	}
}

// onNewEvent is called when a new event arrives.
func (t *liveTab) onNewEvent() {
	if t.autoScroll {
		t.offset = 0
	}
}

// visibleRows returns the number of table rows that fit in the viewport.
func (t *liveTab) visibleRows() int {
	// Subtract header row (1) from available height.
	return max(t.height-1, 1)
}

// view renders the live events table.
func (t *liveTab) view() string {
	events := t.store.Events()

	if len(events) == 0 {
		msg := "  Waiting for WAF events..."
		if t.streamEnded {
			msg = "  Stream ended — container may have stopped."
		}
		return lipgloss.NewStyle().
			Foreground(colorDim).
			Render(msg)
	}

	// Column widths: adapt to terminal width.
	// Fixed columns + spacing, then split the remainder 40/60 between URI and MESSAGE.
	const (
		colTime    = 12
		colIP      = 17
		colMethod  = 7
		colHTTP    = 4
		colRule    = 8
		colSpacing = 12 // spaces between columns
	)

	fixedWidth := colTime + colIP + colMethod + colHTTP + colRule + colSpacing
	flexible := max(t.width-fixedWidth, 20)
	colURI := max(flexible*40/100, 10)
	colMessage := max(flexible-colURI, 10)

	var b strings.Builder

	// Header.
	header := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s",
		colTime, "TIME",
		colIP, "IP",
		colMethod, "METHOD",
		colURI, "URI",
		colHTTP, "HTTP",
		colRule, "RULE",
		colMessage, "MESSAGE",
	)
	b.WriteString(tableHeaderStyle.Render(header))
	b.WriteString("\n")

	// Rows.
	visible := t.visibleRows()
	end := min(t.offset+visible, len(events))

	for i := t.offset; i < end; i++ {
		ev := events[i]
		severity := bestSeverity(ev)

		uri := truncate(ev.URI, colURI)
		ruleID := firstRuleID(ev)
		msg := truncate(firstMessage(ev), colMessage)

		row := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %-*d  %-*s  %-*s",
			colTime, ev.Time.Format("Jan02 15:04"),
			colIP, truncate(ev.ClientIP, colIP),
			colMethod, ev.Method,
			colURI, uri,
			colHTTP, ev.HTTPCode,
			colRule, ruleID,
			colMessage, msg,
		)

		styled := severityStyle(severity).Render(row)
		b.WriteString(styled)
		if i < end-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

// bestSeverity returns the highest severity from an event's rules.
func bestSeverity(ev *parser.Event) string {
	best := ""
	for _, r := range ev.Rules {
		switch r.Severity {
		case "CRITICAL":
			return "CRITICAL"
		case "WARNING":
			if best != "CRITICAL" {
				best = "WARNING"
			}
		case "NOTICE":
			if best == "" {
				best = "NOTICE"
			}
		}
	}
	return best
}

// firstRuleID returns the first rule ID from an event.
func firstRuleID(ev *parser.Event) string {
	if len(ev.Rules) > 0 {
		return ev.Rules[0].RuleID
	}
	return ""
}

// firstMessage returns the first rule message from an event.
func firstMessage(ev *parser.Event) string {
	if len(ev.Rules) > 0 {
		return ev.Rules[0].Message
	}
	return ""
}

// truncate truncates a string to maxLen runes with an ellipsis.
// Operates on runes to avoid slicing multi-byte UTF-8 characters mid-sequence.
func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen == 1 {
		return string(runes[:1])
	}
	return string(runes[:maxLen-1]) + "…"
}

// wordWrap wraps text at maxWidth, breaking on whitespace where possible.
func wordWrap(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return s
	}
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		words := strings.Fields(line)
		lineLen := 0
		for _, w := range words {
			wLen := len([]rune(w))
			if lineLen > 0 && lineLen+1+wLen > maxWidth {
				b.WriteString("\n")
				lineLen = 0
			}
			if lineLen > 0 {
				b.WriteString(" ")
				lineLen++
			}
			b.WriteString(w)
			lineLen += wLen
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// oneline replaces newlines and tabs with spaces, collapses multiple spaces.
func oneline(s string) string {
	r := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ")
	return strings.Join(strings.Fields(r.Replace(s)), " ")
}
