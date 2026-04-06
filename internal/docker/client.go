// Package docker provides a Docker SDK client for interacting with a ModSecurity WAF container.
package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

const (
	defaultContainerName = "modsecurity"
)

// ContainerInfo holds parsed container state and configuration.
type ContainerInfo struct {
	RuleEngine      string
	Paranoia        string
	AnomalyInbound  string
	AnomalyOutbound string
	StartedAt       time.Time
	CRSVersion      string
}

// Client wraps the Docker SDK client and holds the resolved WAF container ID.
type Client struct {
	cli         *dockerclient.Client
	containerID string
}

// NewClient creates a Docker SDK client using environment defaults with API version negotiation.
// It pings the daemon to verify connectivity before returning.
func NewClient(ctx context.Context) (*Client, error) {
	cli, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("docker: failed to create client: %w", err)
	}

	if _, err = cli.Ping(ctx); err != nil {
		cli.Close()
		return nil, fmt.Errorf("docker: failed to ping daemon: %w", err)
	}

	return &Client{cli: cli}, nil
}

// FindContainer locates a running container whose name contains the given substring
// (case-insensitive). Returns the container ID. If name is empty, defaults to "modsecurity".
func (c *Client) FindContainer(ctx context.Context, name string) (string, error) {
	if name == "" {
		name = defaultContainerName
	}

	args := filters.NewArgs(filters.Arg("name", name))
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{Filters: args})
	if err != nil {
		return "", fmt.Errorf("docker: failed to list containers: %w", err)
	}

	// Docker name filter is case-sensitive and does substring matching.
	// We do an additional case-insensitive check on container names.
	lowerName := strings.ToLower(name)
	for _, ctr := range containers {
		for _, n := range ctr.Names {
			// Docker prefixes names with "/".
			if strings.Contains(strings.ToLower(n), lowerName) {
				c.containerID = ctr.ID
				return ctr.ID, nil
			}
		}
	}

	if len(containers) > 0 {
		// Filter matched but our case-insensitive check did not — use first result.
		c.containerID = containers[0].ID
		return containers[0].ID, nil
	}

	return "", fmt.Errorf("docker: no running container matching %q found", name)
}

// logReadCloser wraps a pipe reader produced by demultiplexing a Docker log stream.
type logReadCloser struct {
	pr     *io.PipeReader
	stream io.ReadCloser
}

func (l *logReadCloser) Read(p []byte) (int, error) {
	return l.pr.Read(p)
}

func (l *logReadCloser) Close() error {
	l.stream.Close()
	return l.pr.Close()
}

// StreamLogs returns a streaming reader of the container's log output.
// ModSecurity audit log is sent to stderr via MODSEC_AUDIT_LOG=/dev/stderr.
// Auto-detects whether the Docker stream is multiplexed (8-byte frame headers)
// or raw text, and handles both transparently.
func (c *Client) StreamLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	if containerID == "" {
		containerID = c.containerID
	}
	if containerID == "" {
		return nil, fmt.Errorf("docker: no container ID specified")
	}

	stream, err := c.cli.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "all",
	})
	if err != nil {
		return nil, fmt.Errorf("docker: failed to stream logs: %w", err)
	}

	// Peek at the first byte to detect stream format.
	// Docker multiplexed frames start with stream_type: 0 (stdin), 1 (stdout), 2 (stderr).
	// Raw text starts with a printable ASCII character (>= 0x20).
	peek := make([]byte, 1)
	n, err := stream.Read(peek)
	if err != nil || n == 0 {
		// Empty stream or error — return as-is.
		return stream, nil
	}

	// Reconstruct a reader with the peeked byte prepended.
	combined := io.MultiReader(bytes.NewReader(peek[:n]), stream)

	if peek[0] <= 2 {
		// Multiplexed format — demux with 8-byte frame headers.
		pr, pw := io.Pipe()
		go func() {
			defer stream.Close()
			defer pw.Close()

			src := combined
			header := make([]byte, 8)
			for {
				if _, err := io.ReadFull(src, header); err != nil {
					// Propagate the error so the pipe reader is unblocked.
					pw.CloseWithError(err)
					return
				}
				size := binary.BigEndian.Uint32(header[4:8])
				if size == 0 {
					continue
				}
				if _, err := io.CopyN(pw, src, int64(size)); err != nil {
					// Propagate the error so the pipe reader is unblocked.
					pw.CloseWithError(err)
					return
				}
			}
		}()
		return &logReadCloser{pr: pr, stream: stream}, nil
	}

	// Raw text — return directly (with peeked byte prepended).
	return &rawReadCloser{reader: combined, stream: stream}, nil
}

// rawReadCloser wraps a combined reader with the underlying stream for cleanup.
type rawReadCloser struct {
	reader io.Reader
	stream io.ReadCloser
}

func (r *rawReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *rawReadCloser) Close() error {
	return r.stream.Close()
}

// Inspect returns parsed container information including environment variables and start time.
func (c *Client) Inspect(ctx context.Context, containerID string) (*ContainerInfo, error) {
	if containerID == "" {
		containerID = c.containerID
	}
	if containerID == "" {
		return nil, fmt.Errorf("docker: no container ID specified")
	}

	inspect, err := c.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("docker: failed to inspect container: %w", err)
	}

	info := &ContainerInfo{}
	info.StartedAt = parseStartedAt(inspect)
	parseEnvVars(inspect, info)

	return info, nil
}

// ExecCommand runs a command inside the container and returns its stdout output.
func (c *Client) ExecCommand(ctx context.Context, containerID string, cmd []string) (string, error) {
	if containerID == "" {
		containerID = c.containerID
	}
	if containerID == "" {
		return "", fmt.Errorf("docker: no container ID specified")
	}

	execCfg := container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	}

	execID, err := c.cli.ContainerExecCreate(ctx, containerID, execCfg)
	if err != nil {
		return "", fmt.Errorf("docker: failed to create exec: %w", err)
	}

	resp, err := c.cli.ContainerExecAttach(ctx, execID.ID, container.ExecAttachOptions{})
	if err != nil {
		return "", fmt.Errorf("docker: failed to attach exec: %w", err)
	}
	defer resp.Close()

	var stdout bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, io.Discard, resp.Reader); err != nil {
		return "", fmt.Errorf("docker: failed to read exec output: %w", err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// ContainerID returns the currently resolved container ID.
func (c *Client) ContainerID() string {
	return c.containerID
}

// Close closes the underlying Docker client.
func (c *Client) Close() error {
	if c.cli != nil {
		return c.cli.Close()
	}
	return nil
}

// parseStartedAt extracts the container start time from inspect data.
func parseStartedAt(inspect types.ContainerJSON) time.Time {
	if inspect.ContainerJSONBase != nil && inspect.State != nil && inspect.State.StartedAt != "" {
		t, err := time.Parse(time.RFC3339Nano, inspect.State.StartedAt)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

// parseEnvVars extracts ModSecurity-related environment variables from container config.
func parseEnvVars(inspect types.ContainerJSON, info *ContainerInfo) {
	if inspect.Config == nil {
		return
	}

	for _, env := range inspect.Config.Env {
		key, value, ok := strings.Cut(env, "=")
		if !ok {
			continue
		}

		switch key {
		case "MODSEC_RULE_ENGINE":
			info.RuleEngine = value
		case "PARANOIA":
			info.Paranoia = value
		case "ANOMALY_INBOUND":
			info.AnomalyInbound = value
		case "ANOMALY_OUTBOUND":
			info.AnomalyOutbound = value
		}
	}
}
