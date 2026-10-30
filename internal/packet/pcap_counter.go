package packet

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// PacketCountResult holds packet and byte statistics extracted from a pcap file.
type PacketCountResult struct {
	PcapPath   string  `json:"pcap_path"`
	Protocol   string  `json:"protocol"`
	PacketCount int    `json:"packet_count"`
	TotalBytes int64   `json:"total_bytes"`
	Success    bool    `json:"success"`
	Error      string  `json:"error,omitempty"`
}

// CountHandshakePackets counts packets and total bytes from the first handshake packet to CONNACK.
// It filters by IP/port so only traffic of the benchmark connection is included.
func CountHandshakePackets(pcapPath string, proto string, brokerIP string, port int, keylogPath string) (*PacketCountResult, error) {
	var filter string
	if proto == "tcp-tls" {
		filter = fmt.Sprintf("tcp port %d and host %s", port, brokerIP)
	} else {
		filter = fmt.Sprintf("udp port %d and host %s", port, brokerIP)
	}

	args := []string{
		"-r", pcapPath,
		"-n",
		"-Y", filter,
	}
	if keylogPath != "" {
		args = append(args, "-o", fmt.Sprintf("tls.keylog_file:%s", keylogPath))
	}
	args = append(args,
		"-T", "fields",
		"-E", "separator=\t",
		"-e", "frame.len",
	)

	cmd := exec.Command("tshark", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("tshark packet count failed: %w (stderr: %s)", err, stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	var totalBytes int64
	count := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		v, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			continue
		}
		totalBytes += v
		count++
	}

	return &PacketCountResult{
		PcapPath:    pcapPath,
		Protocol:    proto,
		PacketCount: count,
		TotalBytes:  totalBytes,
		Success:     true,
	}, nil
}
