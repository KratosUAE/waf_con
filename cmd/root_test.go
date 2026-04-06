package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnv_ExtractsIPInfoToken(t *testing.T) {
	// Create a temp directory with a .env file.
	tmpDir := t.TempDir()
	auxDir := filepath.Join(tmpDir, ".aux")
	if err := os.MkdirAll(auxDir, 0755); err != nil {
		t.Fatalf("failed to create .aux dir: %v", err)
	}

	envContent := `# Comment line
SOME_VAR=hello
IPINFO_TOKEN=test-token-123
OTHER_VAR=world
`
	envPath := filepath.Join(auxDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	// Override HOME so loadEnv reads our temp .env.
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	// Reset ipinfoToken before test.
	ipinfoToken = ""

	loadEnv()

	if ipinfoToken != "test-token-123" {
		t.Errorf("expected ipinfoToken = %q, got %q", "test-token-123", ipinfoToken)
	}
}

func TestLoadEnv_HandlesQuotedValues(t *testing.T) {
	tmpDir := t.TempDir()
	auxDir := filepath.Join(tmpDir, ".aux")
	if err := os.MkdirAll(auxDir, 0755); err != nil {
		t.Fatalf("failed to create .aux dir: %v", err)
	}

	envContent := `IPINFO_TOKEN="quoted-token"
`
	envPath := filepath.Join(auxDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	ipinfoToken = ""

	loadEnv()

	if ipinfoToken != "quoted-token" {
		t.Errorf("expected ipinfoToken = %q, got %q", "quoted-token", ipinfoToken)
	}
}

func TestLoadEnv_MissingFileDoesNotPanic(t *testing.T) {
	tmpDir := t.TempDir()

	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	ipinfoToken = ""

	// Should not panic when .aux/.env does not exist.
	loadEnv()

	if ipinfoToken != "" {
		t.Errorf("expected empty ipinfoToken, got %q", ipinfoToken)
	}
}

func TestGetDockerClient_NilReturnsError(t *testing.T) {
	dockerClient = nil

	_, err := getDockerClient()
	if err == nil {
		t.Error("expected error when dockerClient is nil")
	}
}

func TestExecute_VersionFlag(t *testing.T) {
	// Verify that --version does not panic.
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"waf_con", "--version"}

	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("--version returned error: %v", err)
	}
}
