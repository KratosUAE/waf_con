package tui

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"waf_con/internal/docker"
	"waf_con/internal/parser"
	"waf_con/internal/state"
)

// --- Helpers ---

func newTestApp() *App {
	store := state.NewStoreWithCapacity(100)
	info := &docker.ContainerInfo{
		RuleEngine:      "DetectionOnly",
		Paranoia:        "3",
		AnomalyInbound:  "5",
		AnomalyOutbound: "4",
		StartedAt:       time.Now().Add(-3 * 24 * time.Hour),
		CRSVersion:      "4.0.0",
	}
	app := NewApp(store, info, "4.0.0", nil, "", 2, nil)
	app.width = 120
	app.height = 40
	app.propagateSize()
	return app
}

func sampleEvent(ip, method, uri string, httpCode int, ruleID, severity, msg string) *parser.Event {
	return &parser.Event{
		Time:     time.Now(),
		ClientIP: ip,
		Method:   method,
		URI:      uri,
		HTTPCode: httpCode,
		Rules: []parser.RuleMatch{
			{RuleID: ruleID, Message: msg, Severity: severity},
		},
	}
}

func mkKey(key string) tea.KeyPressMsg {
	switch key {
	case "tab":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyTab})
	case "shift+tab":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyTab, Mod: tea.ModShift})
	case "enter":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter})
	case "esc":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape})
	case "up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp})
	case "down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown})
	case "ctrl+c":
		return tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl})
	default:
		if len(key) == 1 {
			return tea.KeyPressMsg(tea.Key{Code: rune(key[0])})
		}
		return tea.KeyPressMsg(tea.Key{Code: -1})
	}
}

// --- App Tests ---

func TestNewApp(t *testing.T) {
	app := newTestApp()
	if app == nil {
		t.Fatal("NewApp returned nil")
	}
	if app.activeTab != tabLive {
		t.Errorf("initial activeTab = %d, want %d", app.activeTab, tabLive)
	}
	if app.refreshInterval != 2*time.Second {
		t.Errorf("refreshInterval = %v, want 2s", app.refreshInterval)
	}
}

func TestNewApp_MinRefreshInterval(t *testing.T) {
	app := NewApp(state.NewStore(), nil, "", nil, "", 0, nil)
	if app.refreshInterval < 1*time.Second {
		t.Errorf("expected minimum refresh interval, got %v", app.refreshInterval)
	}
}

func TestApp_ImplementsTeaModel(t *testing.T) {
	var _ tea.Model = (*App)(nil)
}

func TestApp_Init(t *testing.T) {
	app := newTestApp()
	cmd := app.Init()
	if cmd == nil {
		t.Error("Init() returned nil cmd, want tick command")
	}
}

func TestApp_TabSwitching(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		startTab int
		wantTab  int
	}{
		{"tab forward from live", "tab", tabLive, tabIPs},
		{"tab forward from status wraps", "tab", tabStatus, tabLive},
		{"shift+tab back from live wraps", "shift+tab", tabLive, tabStatus},
		{"shift+tab back from IPs", "shift+tab", tabIPs, tabLive},
		{"press 1", "1", tabIPs, tabLive},
		{"press 2", "2", tabLive, tabIPs},
		{"press 3", "3", tabLive, tabRules},
		{"press 4", "4", tabLive, tabStatus},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newTestApp()
			app.activeTab = tt.startTab
			model, _ := app.handleKey(mkKey(tt.key))
			got := model.(*App).activeTab
			if got != tt.wantTab {
				t.Errorf("after key %q from tab %d: activeTab = %d, want %d",
					tt.key, tt.startTab, got, tt.wantTab)
			}
		})
	}
}

func TestApp_QuitKeys(t *testing.T) {
	for _, key := range []string{"q", "ctrl+c"} {
		t.Run(key, func(t *testing.T) {
			app := newTestApp()
			_, cmd := app.handleKey(mkKey(key))
			if cmd == nil {
				t.Errorf("key %q should produce quit cmd", key)
			}
		})
	}
}

func TestApp_EventMsg(t *testing.T) {
	app := newTestApp()
	ev := sampleEvent("1.2.3.4", "GET", "/test", 403, "942100", "CRITICAL", "SQL Injection")
	msg := logEventMsg{event: ev, ch: make(<-chan *parser.Event)}
	model, _ := app.Update(msg)
	updated := model.(*App)

	if updated.store.TotalEvents() != 1 {
		t.Errorf("store.TotalEvents() = %d, want 1", updated.store.TotalEvents())
	}
}

func TestApp_MultipleEvents(t *testing.T) {
	app := newTestApp()
	for range 10 {
		ev := sampleEvent("1.2.3.4", "GET", "/test", 403, "942100", "CRITICAL", "SQL Injection")
		msg := logEventMsg{event: ev, ch: make(<-chan *parser.Event)}
		app.Update(msg)
	}
	if app.store.TotalEvents() != 10 {
		t.Errorf("store.TotalEvents() = %d, want 10", app.store.TotalEvents())
	}
}

func TestApp_WindowSizeMsg(t *testing.T) {
	app := NewApp(state.NewStore(), nil, "", nil, "", 2, nil)
	msg := tea.WindowSizeMsg{Width: 120, Height: 40}
	model, _ := app.Update(msg)
	updated := model.(*App)

	if updated.width != 120 || updated.height != 40 {
		t.Errorf("dimensions = %dx%d, want 120x40", updated.width, updated.height)
	}
	if updated.liveTab.width != 120 {
		t.Errorf("liveTab.width = %d, want 120", updated.liveTab.width)
	}
}

func TestApp_RefreshTick(t *testing.T) {
	app := newTestApp()
	msg := RefreshTickMsg(time.Now())
	_, cmd := app.Update(msg)
	if cmd == nil {
		t.Error("RefreshTickMsg should return a cmd")
	}
}

func TestApp_View_Uninitialized(t *testing.T) {
	app := NewApp(state.NewStore(), nil, "", nil, "", 2, nil)
	v := app.View()
	if v.Content != "Initializing..." {
		t.Errorf("expected 'Initializing...' for zero-size, got %q", v.Content)
	}
	if !v.AltScreen {
		t.Error("View() should set AltScreen")
	}
}

func TestApp_View_EmptyStore(t *testing.T) {
	app := newTestApp()
	v := app.View()
	if v.Content == "" {
		t.Error("View() returned empty content")
	}
	if !v.AltScreen {
		t.Error("View() should set AltScreen")
	}
}

func TestApp_View_WithEvents(t *testing.T) {
	app := newTestApp()
	app.store.Add(sampleEvent("1.2.3.4", "GET", "/api/test", 403, "942100", "CRITICAL", "SQL Injection"))
	app.store.Add(sampleEvent("5.6.7.8", "POST", "/api/login", 403, "941100", "WARNING", "XSS Attack"))

	v := app.View()
	if !strings.Contains(v.Content, "1.2.3.4") {
		t.Error("expected IP 1.2.3.4 in live view content")
	}
}

func TestApp_View_AllTabs(t *testing.T) {
	app := newTestApp()
	app.store.Add(sampleEvent("1.2.3.4", "GET", "/test", 403, "942100", "CRITICAL", "SQL Injection"))

	for tab := 0; tab < tabCount; tab++ {
		t.Run(tabNames[tab], func(t *testing.T) {
			app.activeTab = tab
			v := app.View()
			if v.Content == "" {
				t.Errorf("tab %d: View() returned empty content", tab)
			}
		})
	}
}

func TestApp_HelpBar_DrillDown(t *testing.T) {
	app := newTestApp()
	app.store.Add(sampleEvent("1.2.3.4", "GET", "/test", 403, "942100", "CRITICAL", "SQL Injection"))

	// Normal IPs tab.
	app.activeTab = tabIPs
	help := app.renderHelpBar()
	if !strings.Contains(help, "Enter:drill-down") {
		t.Error("expected 'Enter:drill-down' in help bar for IPs tab")
	}

	// Drill-down mode.
	app.ipsTab.drillDown = true
	help = app.renderHelpBar()
	if !strings.Contains(help, "Esc:back") {
		t.Error("expected 'Esc:back' in help bar during drill-down")
	}
}

// --- LiveTab Tests ---

func TestLiveTab_EmptyView(t *testing.T) {
	store := state.NewStore()
	tab := newLiveTab(store)
	tab.width = 120
	tab.height = 30

	content := tab.view()
	if !strings.Contains(content, "Waiting") {
		t.Error("expected waiting message for empty live tab")
	}
}

func TestLiveTab_WithEvents(t *testing.T) {
	store := state.NewStore()
	store.Add(sampleEvent("1.2.3.4", "GET", "/test", 403, "942100", "CRITICAL", "SQL Injection"))

	tab := newLiveTab(store)
	tab.width = 120
	tab.height = 30

	content := tab.view()
	if !strings.Contains(content, "1.2.3.4") {
		t.Error("expected IP in live tab view")
	}
	if !strings.Contains(content, "942100") {
		t.Error("expected rule ID in live tab view")
	}
}

func TestLiveTab_AutoScroll(t *testing.T) {
	store := state.NewStore()
	for range 50 {
		store.Add(sampleEvent("1.2.3.4", "GET", "/test", 403, "100", "CRITICAL", "msg"))
	}

	tab := newLiveTab(store)
	tab.width = 120
	tab.height = 10
	if !tab.autoScroll {
		t.Error("expected autoScroll=true initially")
	}

	tab.update("j") // scroll down disables auto-scroll
	if tab.autoScroll {
		t.Error("expected autoScroll=false after scrolling down")
	}
}

func TestLiveTab_ScrollUp_ReenablesAutoScroll(t *testing.T) {
	store := state.NewStore()
	for range 50 {
		store.Add(sampleEvent("1.2.3.4", "GET", "/test", 403, "942100", "CRITICAL", "SQL"))
	}

	tab := newLiveTab(store)
	tab.width = 120
	tab.height = 10

	tab.update("j") // offset = 1, autoScroll = false
	tab.update("k") // offset = 0, autoScroll = true
	if !tab.autoScroll {
		t.Error("expected autoScroll=true after scrolling back to top")
	}
}

func TestLiveTab_OnNewEvent(t *testing.T) {
	tab := newLiveTab(state.NewStore())
	tab.autoScroll = true
	tab.offset = 5

	tab.onNewEvent()
	if tab.offset != 0 {
		t.Errorf("expected offset=0 after onNewEvent with autoScroll, got %d", tab.offset)
	}
}

// --- IPsTab Tests ---

func TestIPsTab_EmptyView(t *testing.T) {
	store := state.NewStore()
	tab := newIPsTab(store, nil)
	tab.width = 120
	tab.height = 30

	content := tab.view()
	if !strings.Contains(content, "No IP data") {
		t.Error("expected empty message for IPs tab")
	}
}

func TestIPsTab_CursorNavigation(t *testing.T) {
	store := state.NewStore()
	store.Add(sampleEvent("1.1.1.1", "GET", "/a", 403, "100", "CRITICAL", "msg"))
	store.Add(sampleEvent("2.2.2.2", "GET", "/b", 403, "100", "CRITICAL", "msg"))
	store.Add(sampleEvent("3.3.3.3", "GET", "/c", 403, "100", "CRITICAL", "msg"))

	tab := newIPsTab(store, nil)
	tab.width = 120
	tab.height = 30

	if tab.cursor != 0 {
		t.Errorf("initial cursor = %d, want 0", tab.cursor)
	}

	tab.update("j")
	if tab.cursor != 1 {
		t.Errorf("after j: cursor = %d, want 1", tab.cursor)
	}

	tab.update("k")
	if tab.cursor != 0 {
		t.Errorf("after k: cursor = %d, want 0", tab.cursor)
	}

	// Should not go below 0.
	tab.update("k")
	if tab.cursor != 0 {
		t.Errorf("after extra k: cursor = %d, want 0", tab.cursor)
	}
}

func TestIPsTab_DrillDown(t *testing.T) {
	store := state.NewStore()
	store.Add(sampleEvent("1.1.1.1", "GET", "/test", 403, "100", "CRITICAL", "msg"))

	tab := newIPsTab(store, nil)
	tab.width = 120
	tab.height = 30

	tab.update("enter")
	if !tab.drillDown {
		t.Error("expected drillDown=true after enter")
	}
	if tab.selectedIP != "1.1.1.1" {
		t.Errorf("selectedIP = %q, want 1.1.1.1", tab.selectedIP)
	}

	content := tab.view()
	if !strings.Contains(content, "1.1.1.1") {
		t.Error("expected IP in drill-down view")
	}

	tab.update("esc")
	if tab.drillDown {
		t.Error("expected drillDown=false after esc")
	}
}

// --- RulesTab Tests ---

func TestRulesTab_EmptyView(t *testing.T) {
	store := state.NewStore()
	tab := newRulesTab(store)
	tab.width = 120
	tab.height = 30

	content := tab.view()
	if !strings.Contains(content, "No rule data") {
		t.Error("expected empty message for rules tab")
	}
}

func TestRulesTab_CursorNavigation(t *testing.T) {
	store := state.NewStore()
	store.Add(sampleEvent("1.1.1.1", "GET", "/a", 403, "100", "CRITICAL", "Rule A"))
	store.Add(sampleEvent("1.1.1.1", "GET", "/b", 403, "200", "WARNING", "Rule B"))

	tab := newRulesTab(store)
	tab.width = 120
	tab.height = 30

	tab.update("j")
	if tab.cursor != 1 {
		t.Errorf("after j: cursor = %d, want 1", tab.cursor)
	}

	tab.update("k")
	if tab.cursor != 0 {
		t.Errorf("after k: cursor = %d, want 0", tab.cursor)
	}
}

func TestRulesTab_DrillDown(t *testing.T) {
	store := state.NewStore()
	store.Add(sampleEvent("1.1.1.1", "GET", "/test", 403, "942100", "CRITICAL", "SQL Injection"))

	tab := newRulesTab(store)
	tab.width = 120
	tab.height = 30

	tab.update("enter")
	if !tab.drillDown {
		t.Error("expected drillDown=true after enter")
	}
	if tab.selectedRule != "942100" {
		t.Errorf("selectedRule = %q, want 942100", tab.selectedRule)
	}

	content := tab.view()
	if !strings.Contains(content, "942100") {
		t.Error("expected rule ID in drill-down view")
	}

	tab.update("esc")
	if tab.drillDown {
		t.Error("expected drillDown=false after esc")
	}
}

// --- StatusTab Tests ---

func TestStatusTab_View(t *testing.T) {
	store := state.NewStore()
	store.Add(sampleEvent("1.1.1.1", "GET", "/test", 403, "100", "CRITICAL", "msg"))

	info := &docker.ContainerInfo{
		RuleEngine:      "DetectionOnly",
		Paranoia:        "3",
		AnomalyInbound:  "5",
		AnomalyOutbound: "4",
		StartedAt:       time.Now().Add(-3 * 24 * time.Hour),
		CRSVersion:      "4.0.0",
	}

	tab := newStatusTab(store, info, "4.0.0")
	tab.width = 120
	tab.height = 30

	content := tab.view()
	if !strings.Contains(content, "DetectionOnly") {
		t.Error("expected RuleEngine in status view")
	}
	if !strings.Contains(content, "4.0.0") {
		t.Error("expected CRS version in status view")
	}
	if !strings.Contains(content, "Total events") {
		t.Error("expected Total events label in status view")
	}
}

func TestStatusTab_NilContainerInfo(t *testing.T) {
	store := state.NewStore()
	tab := newStatusTab(store, nil, "")
	tab.width = 120
	tab.height = 30

	content := tab.view()
	if !strings.Contains(content, "No container info") {
		t.Error("expected 'No container info' message with nil ContainerInfo")
	}
}

// --- Utility Tests ---

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"needs truncation", "hello world", 5, "hell…"},
		{"zero max", "hello", 0, ""},
		{"one char max", "hello", 1, "h"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestBestSeverity(t *testing.T) {
	tests := []struct {
		name       string
		severities []string
		want       string
	}{
		{"single critical", []string{"CRITICAL"}, "CRITICAL"},
		{"warning trumps notice", []string{"NOTICE", "WARNING"}, "WARNING"},
		{"critical trumps all", []string{"NOTICE", "WARNING", "CRITICAL"}, "CRITICAL"},
		{"notice only", []string{"NOTICE"}, "NOTICE"},
		{"unknown", []string{"INFO"}, ""},
		{"empty", []string{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &parser.Event{}
			for _, s := range tt.severities {
				ev.Rules = append(ev.Rules, parser.RuleMatch{Severity: s})
			}
			got := bestSeverity(ev)
			if got != tt.want {
				t.Errorf("bestSeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"minutes only", 5 * time.Minute, "5m"},
		{"hours and minutes", 2*time.Hour + 30*time.Minute, "2h 30m"},
		{"days", 3*24*time.Hour + 14*time.Hour + 22*time.Minute, "3d 14h 22m"},
		{"zero", 0, "0m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.d)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestRenderSparkline(t *testing.T) {
	// All zeros.
	var empty [sparklineBarCount]int
	result := renderSparkline(empty)
	if result == "" {
		t.Error("expected non-empty sparkline for zero data")
	}

	// With data.
	var data [sparklineBarCount]int
	data[0] = 10
	data[15] = 20
	data[29] = 5
	result = renderSparkline(data)
	if result == "" {
		t.Error("expected non-empty sparkline for non-zero data")
	}
}

func TestFormatGeoEntry_NilCache(t *testing.T) {
	got := formatGeoEntry(nil, "1.2.3.4")
	if got != "..." {
		t.Errorf("expected '...' for nil cache, got %q", got)
	}
}

func TestRenderTabBar(t *testing.T) {
	app := newTestApp()
	app.activeTab = tabIPs

	bar := app.renderTabBar()
	if bar == "" {
		t.Error("expected non-empty tab bar")
	}
}
