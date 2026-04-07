package tui

import (
	"fmt"
	"strings"

	lipgloss "charm.land/lipgloss/v2"

	"waf_con/internal/state"
)

// topFPLimit is the maximum number of rules shown in the FP table.
const topFPLimit = 50

// fpTab renders the False Positive candidates table (Tab 4) with drill-down support.
// FP candidates are rules that triggered on HTTP 2xx responses.
type fpTab struct {
	store  *state.Store
	width  int
	height int

	cursor       int
	drillDown    bool
	selectedRule string
	selectedDesc string
	drillOffset  int
}

func newFPTab(store *state.Store) fpTab {
	return fpTab{
		store: store,
	}
}

// update handles key messages for the FP tab.
func (t *fpTab) update(key string) {
	if t.drillDown {
		t.updateDrillDown(key)
		return
	}

	rules := t.store.FPRules(topFPLimit)
	maxCursor := max(len(rules)-1, 0)

	switch key {
	case "j", "down":
		if t.cursor < maxCursor {
			t.cursor++
		}
	case "k", "up":
		if t.cursor > 0 {
			t.cursor--
		}
	case "enter":
		if len(rules) > 0 && t.cursor < len(rules) {
			t.selectedRule = rules[t.cursor].RuleID
			t.selectedDesc = rules[t.cursor].Description
			t.drillDown = true
			t.drillOffset = 0
		}
	}
}

func (t *fpTab) updateDrillDown(key string) {
	switch key {
	case "esc", "escape":
		t.drillDown = false
		t.selectedRule = ""
		t.selectedDesc = ""
	case "j", "down":
		events := t.store.FPEventsByRule(t.selectedRule)
		maxOffset := max(len(events)-t.visibleRows()+4, 0)
		if t.drillOffset < maxOffset {
			t.drillOffset++
		}
	case "k", "up":
		if t.drillOffset > 0 {
			t.drillOffset--
		}
	}
}

func (t *fpTab) visibleRows() int {
	return max(t.height-1, 1)
}

func (t *fpTab) view() string {
	if t.drillDown {
		return t.viewDrillDown()
	}
	return t.viewMain()
}

func (t *fpTab) viewMain() string {
	rules := t.store.FPRules(topFPLimit)

	if len(rules) == 0 {
		return lipgloss.NewStyle().
			Foreground(colorDim).
			Render("  No false positive candidates yet (rules that triggered on HTTP 2xx responses)...")
	}

	const (
		colNum      = 4
		colRuleID   = 9
		colCount    = 7
		colSeverity = 10
		colSpacing  = 10
	)

	fixedWidth := colNum + colRuleID + colCount + colSeverity + colSpacing
	colDesc := max(t.width-fixedWidth, 15)

	var b strings.Builder

	header := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %-*s",
		colNum, "#",
		colRuleID, "RULE ID",
		colCount, "COUNT",
		colSeverity, "SEVERITY",
		colDesc, "DESCRIPTION",
	)
	b.WriteString(tableHeaderStyle.Render(header))
	b.WriteString("\n")

	visible := t.visibleRows()
	offset := 0
	if t.cursor >= visible {
		offset = t.cursor - visible + 1
	}
	end := min(offset+visible, len(rules))

	for i := offset; i < end; i++ {
		rule := rules[i]

		row := fmt.Sprintf("  %-*d  %-*s  %-*d  %-*s  %-*s",
			colNum, i+1,
			colRuleID, rule.RuleID,
			colCount, rule.Count,
			colSeverity, rule.Severity,
			colDesc, truncate(rule.Description, colDesc),
		)

		styled := lipgloss.NewStyle().Foreground(colorWarning).Render(row)
		if i == t.cursor {
			styled = selectedRowStyle.Render(row)
		}
		b.WriteString(styled)
		if i < end-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

func (t *fpTab) viewDrillDown() string {
	events := t.store.FPEventsByRule(t.selectedRule)

	var b strings.Builder

	header := fmt.Sprintf("FP Candidate: %s -- %s -- %d events (HTTP 2xx)",
		t.selectedRule, truncate(t.selectedDesc, 50), len(events))
	b.WriteString(drillDownHeaderStyle.Render(header))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorDim).Render("  Esc to go back"))
	b.WriteString("\n\n")

	const (
		colTime    = 12
		colIP      = 17
		colMethod  = 7
		colHTTP    = 4
		colSpacing = 12
	)

	fixedWidth := colTime + colIP + colMethod + colHTTP + colSpacing
	flexible := max(t.width-fixedWidth, 20)
	colURI := max(flexible*30/100, 10)
	colData := max(flexible-colURI, 10)

	tableHeader := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s",
		colTime, "TIME",
		colIP, "IP",
		colMethod, "METHOD",
		colURI, "URI",
		colHTTP, "HTTP",
		colData, "MATCHED DATA",
	)
	b.WriteString(tableHeaderStyle.Render(tableHeader))
	b.WriteString("\n")

	visible := max(t.visibleRows()-4, 1)
	end := min(t.drillOffset+visible, len(events))

	for i := t.drillOffset; i < end; i++ {
		ev := events[i]
		data := ""
		for _, r := range ev.Rules {
			if r.RuleID == t.selectedRule {
				data = r.Data
				break
			}
		}
		row := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %-*d  %-*s",
			colTime, ev.Time.Format("Jan02 15:04"),
			colIP, truncate(ev.ClientIP, colIP),
			colMethod, ev.Method,
			colURI, truncate(ev.URI, colURI),
			colHTTP, ev.HTTPCode,
			colData, truncate(data, colData),
		)
		b.WriteString(lipgloss.NewStyle().Foreground(colorWarning).Render(row))
		if i < end-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}
