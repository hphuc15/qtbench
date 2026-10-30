package packet

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// TsharkCapture manages background packet capturing via tshark.
type TsharkCapture struct {
	cmd       *exec.Cmd
	pcapFile  string
	stderrBuf bytes.Buffer
	mu        sync.Mutex
	running   bool
}

// StartCapture initiates a background tshark capture session writing to pcapPath.
func StartCapture(iface string, filter string, pcapPath string) (*TsharkCapture, error) {
	if iface == "" {
		iface = "any"
	}

	dir := filepath.Dir(pcapPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create pcap directory %s: %w", dir, err)
	}

	args := []string{
		"-i", iface,
		"-w", pcapPath,
		"-n",
	}

	if filter != "" {
		args = append(args, "-f", filter)
	}

	cmd := exec.Command("tshark", args...)
	tc := &TsharkCapture{
		cmd:      cmd,
		pcapFile: pcapPath,
		running:  true,
	}

	cmd.Stderr = &tc.stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tshark capture: %w", err)
	}

	// Allow tshark a short moment to initialize capture socket
	time.Sleep(300 * time.Millisecond)

	return tc, nil
}

// Stop gracefully signals tshark to stop capturing and flush buffers.
func (tc *TsharkCapture) Stop() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if !tc.running || tc.cmd == nil || tc.cmd.Process == nil {
		return nil
	}

	// Send SIGINT to allow tshark to flush remaining packets cleanly to the pcap file
	_ = tc.cmd.Process.Signal(syscall.SIGINT)

	done := make(chan error, 1)
	go func() {
		done <- tc.cmd.Wait()
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = tc.cmd.Process.Kill()
		<-done
	}

	tc.running = false

	info, err := os.Stat(tc.pcapFile)
	if err != nil {
		return fmt.Errorf("capture file %s not found: %w (stderr: %s)", tc.pcapFile, err, tc.stderrBuf.String())
	}

	if info.Size() == 0 {
		return fmt.Errorf("capture file %s is empty (stderr: %s)", tc.pcapFile, tc.stderrBuf.String())
	}

	return nil
}

// PcapPath returns the path to the output pcap file.
func (tc *TsharkCapture) PcapPath() string {
	return tc.pcapFile
}

// OutputLogs returns any captured stderr logs from tshark.
func (tc *TsharkCapture) OutputLogs() string {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.stderrBuf.String()
}
