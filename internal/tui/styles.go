// Package tui provides the Bubble Tea terminal UI for waf_con.
package tui

import (
	lipgloss "charm.land/lipgloss/v2"
)

// Severity colors for ModSecurity CRS rule severities.
var (
	colorCritical = lipgloss.Color("#FF5555")
	colorWarning  = lipgloss.Color("#FFFF55")
	colorNotice   = lipgloss.Color("#BBBBBB")
	colorDim      = lipgloss.Color("#666666")
	colorAccent   = lipgloss.Color("#7D56F4")
	colorWhite    = lipgloss.Color("#FFFFFF")
	colorGreen    = lipgloss.Color("#55FF55")
)

// Per-tab accent colors (btop-inspired).
var tabAccentColors = [5]string{
	"#55FF55", // Live — green (activity)
	"#55AAFF", // Top IPs — blue (network)
	"#FF8855", // Top Rules — orange (alerts)
	"#FFFF55", // FP — yellow (warning)
	"#AA77FF", // Status — purple (info)
}

// Tab bar styles.
var tabBarStyle = lipgloss.NewStyle().
	PaddingBottom(1)

// Table styles.
var (
	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorAccent).
				BorderBottom(true).
				BorderStyle(lipgloss.NormalBorder())

	selectedRowStyle = lipgloss.NewStyle().
				Reverse(true)
)

// Status tab box styles.
var (
	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorAccent).
			Padding(1, 2)

	boxTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent)
)

// Help bar style at the bottom.
var helpStyle = lipgloss.NewStyle().
	Foreground(colorDim).
	PaddingTop(1)

// Drill-down header style.
var drillDownHeaderStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(colorGreen).
	PaddingBottom(1)

// Pre-allocated severity styles — avoids one allocation per rendered row.
var (
	styleCritical = lipgloss.NewStyle().Foreground(colorCritical)
	styleWarning  = lipgloss.NewStyle().Foreground(colorWarning)
	styleNotice   = lipgloss.NewStyle().Foreground(colorNotice)
	styleDefault  = lipgloss.NewStyle()
	styleInfo     = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
)

// severityStyle returns a pre-allocated style for the given severity level.
func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL":
		return styleCritical
	case "WARNING":
		return styleWarning
	case "NOTICE":
		return styleNotice
	default:
		return styleDefault
	}
}
