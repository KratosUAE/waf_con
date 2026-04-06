package docker

import (
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
)

func TestParseEnvVars(t *testing.T) {
	tests := []struct {
		name    string
		envVars []string
		want    ContainerInfo
	}{
		{
			name: "all vars present",
			envVars: []string{
				"MODSEC_RULE_ENGINE=DetectionOnly",
				"PARANOIA=3",
				"ANOMALY_INBOUND=5",
				"ANOMALY_OUTBOUND=4",
				"OTHER_VAR=ignored",
			},
			want: ContainerInfo{
				RuleEngine:      "DetectionOnly",
				Paranoia:        "3",
				AnomalyInbound:  "5",
				AnomalyOutbound: "4",
			},
		},
		{
			name:    "empty env",
			envVars: []string{},
			want:    ContainerInfo{},
		},
		{
			name: "partial vars",
			envVars: []string{
				"PARANOIA=2",
				"PATH=/usr/bin",
			},
			want: ContainerInfo{
				Paranoia: "2",
			},
		},
		{
			name: "malformed entry without equals",
			envVars: []string{
				"BROKEN_VAR",
				"PARANOIA=1",
			},
			want: ContainerInfo{
				Paranoia: "1",
			},
		},
		{
			name: "value with equals sign",
			envVars: []string{
				"MODSEC_RULE_ENGINE=On=Extra",
			},
			want: ContainerInfo{
				RuleEngine: "On=Extra",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspect := types.ContainerJSON{
				Config: &container.Config{
					Env: tt.envVars,
				},
			}
			var got ContainerInfo
			parseEnvVars(inspect, &got)

			if got.RuleEngine != tt.want.RuleEngine {
				t.Errorf("RuleEngine = %q, want %q", got.RuleEngine, tt.want.RuleEngine)
			}
			if got.Paranoia != tt.want.Paranoia {
				t.Errorf("Paranoia = %q, want %q", got.Paranoia, tt.want.Paranoia)
			}
			if got.AnomalyInbound != tt.want.AnomalyInbound {
				t.Errorf("AnomalyInbound = %q, want %q", got.AnomalyInbound, tt.want.AnomalyInbound)
			}
			if got.AnomalyOutbound != tt.want.AnomalyOutbound {
				t.Errorf("AnomalyOutbound = %q, want %q", got.AnomalyOutbound, tt.want.AnomalyOutbound)
			}
		})
	}
}

func TestParseEnvVars_NilConfig(t *testing.T) {
	inspect := types.ContainerJSON{
		Config: nil,
	}
	var info ContainerInfo
	parseEnvVars(inspect, &info)

	if info.RuleEngine != "" || info.Paranoia != "" {
		t.Errorf("expected empty ContainerInfo for nil config, got %+v", info)
	}
}

func TestParseStartedAt(t *testing.T) {
	tests := []struct {
		name      string
		startedAt string
		wantZero  bool
	}{
		{
			name:      "valid RFC3339Nano",
			startedAt: "2026-04-06T10:00:00.123456789Z",
			wantZero:  false,
		},
		{
			name:      "empty string",
			startedAt: "",
			wantZero:  true,
		},
		{
			name:      "invalid format",
			startedAt: "not-a-time",
			wantZero:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspect := types.ContainerJSON{
				ContainerJSONBase: &types.ContainerJSONBase{
					State: &types.ContainerState{
						StartedAt: tt.startedAt,
					},
				},
			}
			got := parseStartedAt(inspect)

			if tt.wantZero && !got.IsZero() {
				t.Errorf("expected zero time, got %v", got)
			}
			if !tt.wantZero && got.IsZero() {
				t.Errorf("expected non-zero time for input %q", tt.startedAt)
			}
		})
	}
}

func TestParseStartedAt_NilState(t *testing.T) {
	inspect := types.ContainerJSON{}
	got := parseStartedAt(inspect)
	if !got.IsZero() {
		t.Errorf("expected zero time for nil state, got %v", got)
	}
}

func TestContainerInfo_Fields(t *testing.T) {
	info := ContainerInfo{
		RuleEngine:      "On",
		Paranoia:        "3",
		AnomalyInbound:  "5",
		AnomalyOutbound: "4",
		StartedAt:       time.Date(2026, 4, 6, 10, 0, 0, 0, time.UTC),
		CRSVersion:      "4.0.0",
	}

	if info.RuleEngine != "On" {
		t.Errorf("RuleEngine = %q, want %q", info.RuleEngine, "On")
	}
	if info.Paranoia != "3" {
		t.Errorf("Paranoia = %q, want %q", info.Paranoia, "3")
	}
	if info.AnomalyInbound != "5" {
		t.Errorf("AnomalyInbound = %q, want %q", info.AnomalyInbound, "5")
	}
	if info.AnomalyOutbound != "4" {
		t.Errorf("AnomalyOutbound = %q, want %q", info.AnomalyOutbound, "4")
	}
	if info.CRSVersion != "4.0.0" {
		t.Errorf("CRSVersion = %q, want %q", info.CRSVersion, "4.0.0")
	}
	if info.StartedAt.Year() != 2026 {
		t.Errorf("StartedAt year = %d, want 2026", info.StartedAt.Year())
	}
}

func TestClient_ContainerID(t *testing.T) {
	c := &Client{containerID: "abc123"}
	if got := c.ContainerID(); got != "abc123" {
		t.Errorf("ContainerID() = %q, want %q", got, "abc123")
	}
}

func TestClient_Close_NilCli(t *testing.T) {
	c := &Client{cli: nil}
	if err := c.Close(); err != nil {
		t.Errorf("Close() with nil cli returned error: %v", err)
	}
}
