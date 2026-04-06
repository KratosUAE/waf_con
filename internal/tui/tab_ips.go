package tui

import (
	"fmt"
	"strings"

	lipgloss "charm.land/lipgloss/v2"

	"waf_con/internal/geo"
	"waf_con/internal/state"
)

// topIPsLimit is the maximum number of IPs shown in the Top IPs table.
const topIPsLimit = 50

// ipsTab renders the Top IPs table (Tab 2) with drill-down support.
type ipsTab struct {
	store    *state.Store
	geoCache *geo.Cache
	width    int
	height   int

	cursor     int    // selected row in main table
	drillDown  bool   // true when showing events for a specific IP
	selectedIP string // IP being drilled into
	drillOffset int   // scroll offset in drill-down view
}

func newIPsTab(store *state.Store, geoCache *geo.Cache) ipsTab {
	return ipsTab{
		store:    store,
		geoCache: geoCache,
	}
}

// update handles key messages for the IPs tab.
func (t *ipsTab) update(key string) {
	if t.drillDown {
		t.updateDrillDown(key)
		return
	}

	ips := t.store.TopIPs(topIPsLimit)
	maxCursor := max(len(ips)-1, 0)

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
		if len(ips) > 0 && t.cursor < len(ips) {
			t.selectedIP = ips[t.cursor].IP
			t.drillDown = true
			t.drillOffset = 0
		}
	}
}

func (t *ipsTab) updateDrillDown(key string) {
	switch key {
	case "esc", "escape":
		t.drillDown = false
		t.selectedIP = ""
	case "j", "down":
		events := t.store.EventsByIP(t.selectedIP)
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

// visibleRows returns rows available for the table body.
func (t *ipsTab) visibleRows() int {
	return max(t.height-1, 1)
}

// view renders the IPs tab content.
func (t *ipsTab) view() string {
	if t.drillDown {
		return t.viewDrillDown()
	}
	return t.viewMain()
}

func (t *ipsTab) viewMain() string {
	ips := t.store.TopIPs(topIPsLimit)

	if len(ips) == 0 {
		return lipgloss.NewStyle().
			Foreground(colorDim).
			Render("  No IP data yet...")
	}

	const (
		colNum      = 4
		colIP       = 17
		colCount    = 7
		colLastSeen = 12
		colSpacing  = 10
	)

	fixedWidth := colNum + colIP + colCount + colLastSeen + colSpacing
	colGeo := max(t.width-fixedWidth, 10)

	var b strings.Builder

	header := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %-*s",
		colNum, "#",
		colIP, "IP",
		colCount, "COUNT",
		colGeo, "GEO",
		colLastSeen, "LAST SEEN",
	)
	b.WriteString(tableHeaderStyle.Render(header))
	b.WriteString("\n")

	visible := t.visibleRows()
	// Calculate scroll offset so the selected row stays on-screen.
	offset := 0
	if t.cursor >= visible {
		offset = t.cursor - visible + 1
	}
	end := min(offset+visible, len(ips))

	for i := offset; i < end; i++ {
		ip := ips[i]
		geoStr := ip.Geo
		if geoStr == "" {
			geoStr = formatGeoEntry(t.geoCache, ip.IP)
		}

		row := fmt.Sprintf("  %-*d  %-*s  %-*d  %-*s  %-*s",
			colNum, i+1,
			colIP, truncate(ip.IP, colIP),
			colCount, ip.Count,
			colGeo, truncate(geoStr, colGeo),
			colLastSeen, ip.LastSeen.Format("Jan02 15:04"),
		)

		if i == t.cursor {
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

func (t *ipsTab) viewDrillDown() string {
	events := t.store.EventsByIP(t.selectedIP)
	geoStr := formatGeoEntry(t.geoCache, t.selectedIP)

	var b strings.Builder

	header := fmt.Sprintf("IP: %s -- %s -- %d events", t.selectedIP, geoStr, len(events))
	b.WriteString(drillDownHeaderStyle.Render(header))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorDim).Render("  Esc to go back"))
	b.WriteString("\n\n")

	const (
		colTime    = 12
		colMethod  = 7
		colHTTP    = 4
		colRule    = 8
		colSpacing = 12
	)

	fixedWidth := colTime + colMethod + colHTTP + colRule + colSpacing
	flexible := max(t.width-fixedWidth, 20)
	colURI := max(flexible*40/100, 10)
	colMessage := max(flexible-colURI, 10)

	tableHeader := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s",
		colTime, "TIME",
		colMethod, "METHOD",
		colURI, "URI",
		colHTTP, "HTTP",
		colRule, "RULE",
		colMessage, "MESSAGE",
	)
	b.WriteString(tableHeaderStyle.Render(tableHeader))
	b.WriteString("\n")

	visible := max(t.visibleRows()-4, 1)
	end := min(t.drillOffset+visible, len(events))

	for i := t.drillOffset; i < end; i++ {
		ev := events[i]
		severity := bestSeverity(ev)
		row := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*d  %-*s  %-*s",
			colTime, ev.Time.Format("Jan02 15:04"),
			colMethod, ev.Method,
			colURI, truncate(ev.URI, colURI),
			colHTTP, ev.HTTPCode,
			colRule, firstRuleID(ev),
			colMessage, truncate(firstMessage(ev), colMessage),
		)
		b.WriteString(severityStyle(severity).Render(row))
		if i < end-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

// formatGeoEntry formats geo information for an IP from the cache.
func formatGeoEntry(cache *geo.Cache, ip string) string {
	if cache == nil {
		return "..."
	}
	entry, ok := cache.Get(ip)
	if !ok {
		return "..."
	}
	parts := make([]string, 0, 3)
	if entry.City != "" {
		parts = append(parts, entry.City)
	}
	if entry.Country != "" {
		parts = append(parts, entry.Country)
	}
	if entry.Org != "" {
		parts = append(parts, entry.Org)
	}
	if len(parts) == 0 {
		return "..."
	}
	return strings.Join(parts, ", ")
}
