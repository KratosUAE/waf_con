// Package tui provides the Bubble Tea terminal UI for waf_con.
package tui

import (
	"context"
	"io"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"

	"waf_con/internal/docker"
	"waf_con/internal/geo"
	"waf_con/internal/parser"
	"waf_con/internal/state"
)

// Tab indices.
const (
	tabLive   = 0
	tabIPs    = 1
	tabRules  = 2
	tabFP     = 3
	tabStatus = 4
	tabCount  = 5
)

// tabNames are the display labels for each tab.
var tabNames = [tabCount]string{"1 Live", "2 Top IPs", "3 Top Rules", "4 FP", "5 Status"}

// RefreshTickMsg is sent periodically to trigger UI refresh and geo lookups.
type RefreshTickMsg time.Time

// GeoResultMsg signals that geo lookups have completed and the cache is updated.
type GeoResultMsg struct{}

// App is the root Bubble Tea model for the waf_con TUI.
type App struct {
	store           *state.Store
	containerInfo   *docker.ContainerInfo
	crsVersion      string
	geoCache        *geo.Cache
	ipinfoToken     string
	refreshInterval time.Duration
	logStream       io.ReadCloser

	activeTab    int
	width        int
	height       int
	streamEnded  bool // set when the Docker log stream is exhausted

	liveTab   liveTab
	ipsTab    ipsTab
	rulesTab  rulesTab
	fpTab     fpTab
	statusTab statusTab
}

// NewApp creates a new App model with all required dependencies.
// logStream is the Docker log reader — streaming starts inside Init().
func NewApp(
	store *state.Store,
	containerInfo *docker.ContainerInfo,
	crsVersion string,
	geoCache *geo.Cache,
	ipinfoToken string,
	refreshInterval int,
	logStream io.ReadCloser,
) *App {
	interval := max(time.Duration(refreshInterval)*time.Second, 2*time.Second)

	return &App{
		store:           store,
		containerInfo:   containerInfo,
		crsVersion:      crsVersion,
		geoCache:        geoCache,
		ipinfoToken:     ipinfoToken,
		refreshInterval: interval,
		logStream:       logStream,
		liveTab:         newLiveTab(store),
		ipsTab:          newIPsTab(store, geoCache),
		rulesTab:        newRulesTab(store),
		fpTab:           newFPTab(store),
		statusTab:       newStatusTab(store, containerInfo, crsVersion),
	}
}

// Init implements tea.Model. Starts log streaming and periodic refresh.
func (a *App) Init() tea.Cmd {
	return tea.Batch(tickRefresh(a.refreshInterval), a.streamLogsCmd())
}

// logEventMsg wraps a parsed event and the channel to read the next one.
type logEventMsg struct {
	event *parser.Event
	ch    <-chan *parser.Event
}

// logDoneMsg signals the log stream is exhausted.
type logDoneMsg struct{}

// streamLogsCmd returns a tea.Cmd that starts reading the Docker log stream.
// It sends one event at a time back to Update(), which chains the next read.
func (a *App) streamLogsCmd() tea.Cmd {
	logStream := a.logStream
	return func() tea.Msg {
		ch := make(chan *parser.Event, 64)
		go func() {
			parser.ParseStream(logStream, ch)
			// ch is closed by ParseStream when the reader is exhausted.
		}()
		// Wait for the first event.
		ev, ok := <-ch
		if !ok {
			return logDoneMsg{}
		}
		return logEventMsg{event: ev, ch: ch}
	}
}

// waitForNextEvent returns a tea.Cmd that waits for the next event from the channel.
func waitForNextEvent(ch <-chan *parser.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return logDoneMsg{}
		}
		return logEventMsg{event: ev, ch: ch}
	}
}

// Update implements tea.Model.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		a.propagateSize()
		return a, nil

	case tea.KeyPressMsg:
		return a.handleKey(msg)

	case logEventMsg:
		a.store.Add(msg.event)
		a.liveTab.onNewEvent()
		// Chain: immediately wait for the next event from the stream.
		return a, waitForNextEvent(msg.ch)

	case logDoneMsg:
		// Log stream exhausted (container stopped or stream closed).
		a.streamEnded = true
		a.liveTab.streamEnded = true
		return a, nil

	case RefreshTickMsg:
		a.store.CleanOldBuckets()
		return a, tea.Batch(tickRefresh(a.refreshInterval), a.batchGeoCmd())

	case GeoResultMsg:
		// Geo cache has been updated; the next render will pick up new data.
		// Also update the store's geo fields for TopIPs display.
		a.syncGeoToStore()
		return a, nil
	}

	return a, nil
}

// View implements tea.Model.
func (a *App) View() tea.View {
	if a.width == 0 || a.height == 0 {
		v := tea.NewView("Initializing...")
		v.AltScreen = true
		return v
	}

	var sections []string

	// Tab bar.
	sections = append(sections, a.renderTabBar())

	// Active tab content.
	contentHeight := max(a.height-4, 1) // tab bar (2 lines) + help bar (2 lines)
	content := a.renderActiveTab()
	// Pad content to fill available space.
	contentLines := strings.Count(content, "\n") + 1
	if contentLines < contentHeight {
		content += strings.Repeat("\n", contentHeight-contentLines)
	}
	sections = append(sections, content)

	// Help bar.
	sections = append(sections, a.renderHelpBar())

	body := lipgloss.JoinVertical(lipgloss.Left, sections...)

	v := tea.NewView(body)
	v.AltScreen = true
	return v
}

// handleKey processes key press messages.
func (a *App) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global keys first.
	switch key {
	case "q", "ctrl+c":
		return a, tea.Quit
	case "tab":
		a.activeTab = (a.activeTab + 1) % tabCount
		return a, nil
	case "shift+tab":
		a.activeTab = (a.activeTab - 1 + tabCount) % tabCount
		return a, nil
	case "1":
		a.activeTab = tabLive
		return a, nil
	case "2":
		a.activeTab = tabIPs
		return a, nil
	case "3":
		a.activeTab = tabRules
		return a, nil
	case "4":
		a.activeTab = tabFP
		return a, nil
	case "5":
		a.activeTab = tabStatus
		return a, nil
	}

	// Delegate to active tab.
	switch a.activeTab {
	case tabLive:
		a.liveTab.update(key)
	case tabIPs:
		a.ipsTab.update(key)
	case tabRules:
		a.rulesTab.update(key)
	case tabFP:
		a.fpTab.update(key)
	}

	return a, nil
}

// propagateSize updates dimensions on all sub-tabs.
func (a *App) propagateSize() {
	contentHeight := max(a.height-4, 1)
	a.liveTab.width = a.width
	a.liveTab.height = contentHeight
	a.ipsTab.width = a.width
	a.ipsTab.height = contentHeight
	a.rulesTab.width = a.width
	a.rulesTab.height = contentHeight
	a.fpTab.width = a.width
	a.fpTab.height = contentHeight
	a.statusTab.width = a.width
	a.statusTab.height = contentHeight
}

// renderTabBar renders the tab bar at the top with a clock in the right corner.
func (a *App) renderTabBar() string {
	var tabs []string
	for i, name := range tabNames {
		color := lipgloss.Color(tabAccentColors[i])
		if i == a.activeTab {
			tabs = append(tabs, lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#000000")).
				Background(color).
				Padding(0, 2).
				Render(name))
		} else {
			tabs = append(tabs, lipgloss.NewStyle().
				Foreground(color).
				Padding(0, 2).
				Render(name))
		}
	}
	tabsPart := lipgloss.JoinHorizontal(lipgloss.Top, tabs...)

	// Clock in the right corner.
	clock := time.Now().Format("15:04:05")
	clockStyled := lipgloss.NewStyle().Foreground(colorDim).Render(clock)

	// Pad between tabs and clock to push clock to the right.
	tabsWidth := lipgloss.Width(tabsPart)
	clockWidth := lipgloss.Width(clockStyled)
	gap := a.width - tabsWidth - clockWidth - 2
	if gap < 1 {
		// Terminal too narrow for clock — show tabs only.
		return tabBarStyle.Render(tabsPart)
	}
	return tabBarStyle.Render(tabsPart + strings.Repeat(" ", gap) + clockStyled)
}

// renderActiveTab renders the content of the currently selected tab.
func (a *App) renderActiveTab() string {
	switch a.activeTab {
	case tabLive:
		return a.liveTab.view()
	case tabIPs:
		return a.ipsTab.view()
	case tabRules:
		return a.rulesTab.view()
	case tabFP:
		return a.fpTab.view()
	case tabStatus:
		return a.statusTab.view()
	default:
		return ""
	}
}

// renderHelpBar renders the help text at the bottom.
func (a *App) renderHelpBar() string {
	help := "  q:quit  Tab:switch  j/k:scroll"
	switch a.activeTab {
	case tabIPs:
		if a.ipsTab.detailView {
			help += "  Esc:back"
		} else if a.ipsTab.drillDown {
			help += "  Enter:detail  Esc:back"
		} else {
			help += "  Enter:drill-down"
		}
	case tabRules:
		if a.rulesTab.detailView {
			help += "  Esc:back"
		} else if a.rulesTab.drillDown {
			help += "  Enter:detail  Esc:back"
		} else {
			help += "  Enter:drill-down"
		}
	case tabFP:
		if a.fpTab.detailView {
			help += "  Esc:back"
		} else if a.fpTab.drillDown {
			help += "  Enter:detail  Esc:back"
		} else {
			help += "  Enter:drill-down"
		}
	}
	return helpStyle.Render(help)
}

// tickRefresh returns a tea.Tick command that fires a RefreshTickMsg.
func tickRefresh(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return RefreshTickMsg(t)
	})
}

// batchGeoCmd triggers geo lookups for all uncached IPs in the store.
func (a *App) batchGeoCmd() tea.Cmd {
	if a.ipinfoToken == "" || a.geoCache == nil {
		return nil
	}

	ips := a.store.TopIPs(topIPsLimit)
	ipList := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipList = append(ipList, ip.IP)
	}

	uncached := a.geoCache.FilterUncached(ipList)
	if len(uncached) == 0 {
		return nil
	}

	token := a.ipinfoToken
	cache := a.geoCache
	return func() tea.Msg {
		// 5s is sufficient for ipinfo.io; avoids a 30s hang on quit.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = geo.Lookup(ctx, cache, uncached, token)
		return GeoResultMsg{}
	}
}

// syncGeoToStore updates the store's geo strings from the cache.
func (a *App) syncGeoToStore() {
	ips := a.store.TopIPs(topIPsLimit)
	for _, ip := range ips {
		if ip.Geo != "" {
			continue
		}
		entry, ok := a.geoCache.Get(ip.IP)
		if !ok {
			continue
		}
		geoStr := formatGeoString(entry)
		a.store.SetGeo(ip.IP, geoStr)
	}
}

// formatGeoString formats a GeoEntry as "City, CC, Org".
func formatGeoString(entry geo.GeoEntry) string {
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
		return ""
	}
	return strings.Join(parts, ", ")
}
