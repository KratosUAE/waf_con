package tui

import (
	"fmt"
	"strings"
	"time"

	lipgloss "charm.land/lipgloss/v2"

	"waf_con/internal/docker"
	"waf_con/internal/state"
)

// sparklineChars is the set of Unicode block characters used for sparkline rendering.
// Index 0 is the shortest bar, index 7 is the tallest.
const sparklineChars = "▁▂▃▄▅▆▇█"

// sparklineRunes are the individual rune values extracted from sparklineChars.
var sparklineRunes = []rune(sparklineChars)

// sparklineBarCount is the number of bars in the sparkline display.
const sparklineBarCount = 30

// statusTab renders the Status dashboard (Tab 5).
type statusTab struct {
	store         *state.Store
	containerInfo *docker.ContainerInfo
	crsVersion    string
	width         int
	height        int
}

func newStatusTab(store *state.Store, containerInfo *docker.ContainerInfo, crsVersion string) statusTab {
	return statusTab{
		store:         store,
		containerInfo: containerInfo,
		crsVersion:    crsVersion,
	}
}

// view renders the status tab with two side-by-side boxes.
func (t *statusTab) view() string {
	boxWidth := max((t.width-4)/2, 30)

	engineBox := t.renderEngineBox(boxWidth)
	activityBox := t.renderActivityBox(boxWidth)

	return lipgloss.JoinHorizontal(lipgloss.Top, engineBox, "  ", activityBox)
}

func (t *statusTab) renderEngineBox(width int) string {
	var b strings.Builder

	info := t.containerInfo
	if info == nil {
		b.WriteString("  No container info available")
		return boxStyle.Width(width).Render(
			boxTitleStyle.Render("Engine") + "\n\n" + b.String(),
		)
	}

	ruleEngine := info.RuleEngine
	if ruleEngine == "" {
		ruleEngine = "N/A"
	}
	paranoia := info.Paranoia
	if paranoia == "" {
		paranoia = "N/A"
	}
	anomalyIn := info.AnomalyInbound
	if anomalyIn == "" {
		anomalyIn = "N/A"
	}
	anomalyOut := info.AnomalyOutbound
	if anomalyOut == "" {
		anomalyOut = "N/A"
	}
	crs := t.crsVersion
	if crs == "" {
		crs = "N/A"
	}

	uptime := "N/A"
	if !info.StartedAt.IsZero() {
		uptime = formatDuration(time.Since(info.StartedAt))
	}

	fmt.Fprintf(&b, "Mode:      %s\n", ruleEngine)
	fmt.Fprintf(&b, "CRS:       %s\n", crs)
	fmt.Fprintf(&b, "Paranoia:  %s\n", paranoia)
	fmt.Fprintf(&b, "Anomaly:   %s/%s (in/out)\n", anomalyIn, anomalyOut)
	fmt.Fprintf(&b, "Uptime:    %s", uptime)

	return boxStyle.Width(width).Render(
		boxTitleStyle.Render("Engine") + "\n\n" + b.String(),
	)
}

func (t *statusTab) renderActivityBox(width int) string {
	var b strings.Builder

	totalEvents := t.store.TotalEvents()
	epm := t.store.EventsPerMinute()
	uniqueIPs := t.store.UniqueIPs()
	uniqueRules := t.store.UniqueRules()

	fmt.Fprintf(&b, "Total events:  %d\n", totalEvents)
	fmt.Fprintf(&b, "Events/min:    %.1f\n", epm)
	fmt.Fprintf(&b, "Unique IPs:    %d\n", uniqueIPs)
	fmt.Fprintf(&b, "Unique rules:  %d\n", uniqueRules)
	b.WriteString("\n")
	b.WriteString(renderSparkline(t.store.Sparkline()))
	b.WriteString(" (last 30min)")

	return boxStyle.Width(width).Render(
		boxTitleStyle.Render("Activity") + "\n\n" + b.String(),
	)
}

// renderSparkline converts sparkline data to a string of Unicode block characters.
func renderSparkline(data [sparklineBarCount]int) string {
	maxVal := 0
	for _, v := range data {
		if v > maxVal {
			maxVal = v
		}
	}

	if maxVal == 0 {
		return strings.Repeat(string(sparklineRunes[0]), sparklineBarCount)
	}

	numLevels := len(sparklineRunes)
	var b strings.Builder
	b.Grow(sparklineBarCount * 4) // UTF-8 runes can be up to 4 bytes

	for _, v := range data {
		idx := min((v*(numLevels-1))/maxVal, numLevels-1)
		b.WriteRune(sparklineRunes[idx])
	}

	return lipgloss.NewStyle().Foreground(colorGreen).Render(b.String())
}

// formatDuration formats a duration as "Xd Yh Zm".
func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
