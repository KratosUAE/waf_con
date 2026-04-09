// Package cmd provides CLI command definitions using Cobra.
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"waf_con/internal/docker"
	"waf_con/internal/geo"
	"waf_con/internal/state"
	"waf_con/internal/tui"
)

var (
	dockerClient  *docker.Client
	ipinfoToken   string
	containerName string
	refreshSec    int
	debugMode     bool

	// signalStop is the stop function from signal.NotifyContext.
	// It is called in PersistentPostRun to release the OS signal handler.
	signalStop context.CancelFunc
)

// Version is set at build time via ldflags.
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:     "waf_con",
	Short:   "ModSecurity WAF monitoring TUI dashboard",
	Version: Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load IPINFO_TOKEN from ~/.aux/.env, then check env var as fallback.
		loadEnv()
		if ipinfoToken == "" {
			ipinfoToken = os.Getenv("IPINFO_TOKEN")
		}

		// Set up signal-aware context so the whole tree gets clean cancellation.
		// signalStop is stored in a package-level var and called in PersistentPostRun
		// to ensure the OS signal handler is released when the command exits.
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
		signalStop = stop
		cmd.SetContext(ctx)

		// Create Docker client.
		cli, err := docker.NewClient(ctx)
		if err != nil {
			return fmt.Errorf("failed to connect to Docker: %w", err)
		}
		dockerClient = cli

		// Find ModSecurity container.
		if _, err := dockerClient.FindContainer(ctx, containerName); err != nil {
			dockerClient.Close()
			return err
		}

		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if signalStop != nil {
			signalStop()
		}
		if dockerClient != nil {
			dockerClient.Close()
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		cli, err := getDockerClient()
		if err != nil {
			return err
		}

		// Inspect container for environment variables (RuleEngine, Paranoia, etc).
		containerInfo, err := cli.Inspect(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to inspect container: %w", err)
		}

		// Read CRS version from the container filesystem.
		crsVersion, err := cli.ExecCommand(ctx, "", []string{"cat", "/opt/owasp-crs/VERSION"})
		if err != nil || crsVersion == "" {
			// Non-fatal: the container may not have this file or the command
			// may succeed but return no output (e.g. empty VERSION file).
			crsVersion = "unknown"
		}
		containerInfo.CRSVersion = crsVersion

		// Create geo cache at ~/.cache/waf-con/geo.json.
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to determine home directory: %w", err)
		}
		geoCachePath := filepath.Join(home, ".cache", "waf-con", "geo.json")
		geoCache, err := geo.NewCache(geoCachePath)
		if err != nil {
			return fmt.Errorf("failed to create geo cache: %w", err)
		}

		// Create in-memory state store.
		store := state.NewStore()

		// Open Docker log stream (will be read by TUI via Init command).
		logStream, err := cli.StreamLogs(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to start log stream: %w", err)
		}

		// Debug mode: dump raw stream to file and exit (no TUI).
		if debugMode {
			return runDebug(logStream)
		}

		// Create TUI model — logStream is passed in so streaming starts inside Init().
		app := tui.NewApp(store, containerInfo, crsVersion, geoCache, ipinfoToken, refreshSec, logStream)

		// Create and run Bubble Tea program — blocks until the user quits.
		p := tea.NewProgram(app)
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("TUI exited with error: %w", err)
		}

		// Persist geo cache on exit.
		if saveErr := geoCache.Save(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to save geo cache: %v\n", saveErr)
		}

		return nil
	},
}

// getDockerClient returns the Docker client or an error if it was not initialized.
func getDockerClient() (*docker.Client, error) {
	if dockerClient == nil {
		return nil, fmt.Errorf("docker client not initialized — is Docker running?")
	}
	return dockerClient, nil
}

func init() {
	rootCmd.PersistentFlags().StringVar(&containerName, "container", "", `Container name override (default: auto-detect "modsecurity")`)
	rootCmd.PersistentFlags().IntVar(&refreshSec, "refresh", 2, "Refresh interval in seconds")
	rootCmd.PersistentFlags().BoolVar(&debugMode, "debug", false, "Dump raw Docker log stream to /tmp/waf_con_debug.log and stdout")
}

// runDebug reads from the log stream and dumps raw data for diagnosis.
func runDebug(stream io.ReadCloser) error {
	defer stream.Close()

	debugFile, err := os.Create("/tmp/waf_con_debug.log")
	if err != nil {
		return fmt.Errorf("failed to create debug file: %w", err)
	}
	defer debugFile.Close()

	fmt.Println("Debug mode: reading Docker log stream...")
	fmt.Println("Raw bytes will be written to /tmp/waf_con_debug.log")
	fmt.Println("First 2048 bytes also shown as hex below:")
	fmt.Println("Press Ctrl+C to stop.")
	fmt.Println()

	buf := make([]byte, 2048)
	totalRead := 0
	for totalRead < 2048 {
		n, readErr := stream.Read(buf[totalRead:])
		if n > 0 {
			debugFile.Write(buf[totalRead : totalRead+n])
			totalRead += n
		}
		if readErr != nil {
			fmt.Printf("Stream read error after %d bytes: %v\n", totalRead, readErr)
			break
		}
	}

	if totalRead == 0 {
		fmt.Println("WARNING: 0 bytes read from stream!")
		return nil
	}

	// Show hex dump.
	fmt.Printf("Read %d bytes. Hex dump:\n", totalRead)
	for i := 0; i < totalRead; i += 16 {
		end := min(i+16, totalRead)
		// Hex part.
		fmt.Printf("%04x: ", i)
		for j := i; j < end; j++ {
			fmt.Printf("%02x ", buf[j])
		}
		for j := end; j < i+16; j++ {
			fmt.Print("   ")
		}
		// ASCII part.
		fmt.Print(" |")
		for j := i; j < end; j++ {
			if buf[j] >= 32 && buf[j] < 127 {
				fmt.Printf("%c", buf[j])
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}

	return nil
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

// loadEnv reads key=value pairs from ~/.aux/.env.
// Lines starting with # are skipped. Only IPINFO_TOKEN is extracted.
func loadEnv() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	f, err := os.Open(filepath.Join(home, ".aux", ".env"))
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		// Remove surrounding quotes if present.
		value = strings.Trim(value, `"'`)

		if key == "IPINFO_TOKEN" {
			ipinfoToken = value
		}
	}
}
