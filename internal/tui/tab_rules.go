package tui

import (
	"fmt"
	"strings"

	lipgloss "charm.land/lipgloss/v2"

	"waf_con/internal/state"
)

// topRulesLimit is the maximum number of rules shown in the Top Rules table.
const topRulesLimit = 50

// rulesTab renders the Top Rules table (Tab 3) with drill-down support.
type rulesTab struct {
	store  *state.Store
	width  int
	height int

	cursor       int    // selected row in main table
	drillDown    bool   // true when showing events for a specific rule
	selectedRule string // rule ID being drilled into
	selectedDesc string // description of selected rule
	drillCursor  int    // selected row in drill-down table
	drillOffset  int    // scroll offset in drill-down view
	detailView   bool   // true when showing full detail of a single event
}

func newRulesTab(store *state.Store) rulesTab {
	return rulesTab{
		store: store,
	}
}

// update handles key messages for the rules tab.
func (t *rulesTab) update(key string) {
	if t.drillDown {
		t.updateDrillDown(key)
		return
	}

	rules := t.store.TopRules(topRulesLimit)
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
			t.drillCursor = 0
		}
	}
}

func (t *rulesTab) updateDrillDown(key string) {
	events := t.store.EventsByRule(t.selectedRule)

	// Guard: if detail view targets a row that no longer exists, exit detail.
	if t.detailView && t.drillCursor >= len(events) {
		t.detailView = false
	}

	if t.detailView {
		switch key {
		case "esc", "escape", "enter":
			t.detailView = false
		}
		return
	}
	maxCursor := max(len(events)-1, 0)

	switch key {
	case "esc", "escape":
		t.drillDown = false
		t.selectedRule = ""
		t.selectedDesc = ""
		t.drillCursor = 0
	case "j", "down":
		if t.drillCursor < maxCursor {
			t.drillCursor++
		}
	case "k", "up":
		if t.drillCursor > 0 {
			t.drillCursor--
		}
	case "enter":
		if len(events) > 0 && t.drillCursor < len(events) {
			t.detailView = true
		}
	}

	visible := max(t.visibleRows()-4, 1)
	if t.drillCursor >= t.drillOffset+visible {
		t.drillOffset = t.drillCursor - visible + 1
	}
	if t.drillCursor < t.drillOffset {
		t.drillOffset = t.drillCursor
	}
}

// visibleRows returns rows available for the table body.
func (t *rulesTab) visibleRows() int {
	return max(t.height-1, 1)
}

// view renders the rules tab content.
func (t *rulesTab) view() string {
	if t.detailView {
		return t.viewDetail()
	}
	if t.drillDown {
		return t.viewDrillDown()
	}
	return t.viewMain()
}

func (t *rulesTab) viewMain() string {
	rules := t.store.TopRules(topRulesLimit)

	if len(rules) == 0 {
		return lipgloss.NewStyle().
			Foreground(colorDim).
			Render("  No rule data yet...")
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
	// Calculate scroll offset so the selected row stays on-screen.
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

		styled := severityStyle(rule.Severity).Render(row)
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

func (t *rulesTab) viewDrillDown() string {
	events := t.store.EventsByRule(t.selectedRule)

	var b strings.Builder

	header := fmt.Sprintf("Rule %s -- %s -- %d events",
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
			colData, truncate(oneline(data), colData),
		)
		if i == t.drillCursor {
			b.WriteString(selectedRowStyle.Render(row))
		} else {
			b.WriteString(row)
		}
		if i < end-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

// viewDetail shows full event details with word-wrapped matched data.
func (t *rulesTab) viewDetail() string {
	events := t.store.EventsByRule(t.selectedRule)
	if t.drillCursor >= len(events) {
		return t.viewDrillDown() // guard handled in Update
	}
	ev := events[t.drillCursor]

	data := ""
	msg := ""
	for _, r := range ev.Rules {
		if r.RuleID == t.selectedRule {
			data = r.Data
			msg = r.Message
			break
		}
	}

	var b strings.Builder

	title := fmt.Sprintf("Rule %s — %s", t.selectedRule, msg)
	b.WriteString(drillDownHeaderStyle.Render(title))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorDim).Render("  Esc/Enter to go back"))
	b.WriteString("\n\n")

	infoStyle := styleInfo
	b.WriteString(infoStyle.Render("  Time:   "))
	b.WriteString(ev.Time.Format("Jan02 15:04:05"))
	b.WriteString("\n")
	b.WriteString(infoStyle.Render("  IP:     "))
	b.WriteString(ev.ClientIP)
	b.WriteString("\n")
	b.WriteString(infoStyle.Render("  Method: "))
	b.WriteString(ev.Method)
	b.WriteString("\n")
	b.WriteString(infoStyle.Render("  URI:    "))
	b.WriteString(ev.URI)
	b.WriteString("\n")
	b.WriteString(infoStyle.Render("  HTTP:   "))
	b.WriteString(fmt.Sprintf("%d", ev.HTTPCode))
	b.WriteString("\n\n")

	b.WriteString(infoStyle.Render("  Matched Data:"))
	b.WriteString("\n")

	// Word-wrap the data to fit the terminal width.
	wrapWidth := max(t.width-4, 20)
	wrapped := wordWrap(data, wrapWidth)
	for _, line := range strings.Split(wrapped, "\n") {
		b.WriteString("  ")
		b.WriteString(lipgloss.NewStyle().Foreground(colorWarning).Render(line))
		b.WriteString("\n")
	}

	return b.String()
}
