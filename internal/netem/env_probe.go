package netem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EnvironmentProfile stores network characterization metrics according to Table 4.
type EnvironmentProfile struct {
	Environment   string    `json:"environment"` // "wired" or "wireless"
	TargetHost    string    `json:"target_host"`
	Timestamp     time.Time `json:"timestamp"`
	BandwidthUDP  float64   `json:"bandwidth_udp_mbps"`
	ThroughputTCP float64   `json:"throughput_tcp_mbps"`
	RTTAvgMs      float64   `json:"rtt_avg_ms"`
	RTTMinMs      float64   `json:"rtt_min_ms"`
	RTTMaxMs      float64   `json:"rtt_max_ms"`
	JitterMs      float64   `json:"jitter_ms"`
	PacketLossPct float64   `json:"packet_loss_pct"`
	RSSI          string    `json:"rssi,omitempty"`
}

// PingHost executes a quick ping probe to measure baseline RTT in milliseconds.
func PingHost(ctx context.Context, targetHost string, count int) (float64, error) {
	if count <= 0 {
		count = 3
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	out, err := runCommand(timeoutCtx, "ping", "-c", strconv.Itoa(count), "-W", "1", "-i", "0.2", targetHost)
	if err != nil {
		return 0.0, err
	}
	var prof EnvironmentProfile
	parsePingOutput(out, &prof)
	return prof.RTTAvgMs, nil
}

// ProbeEnvironment performs ping and iperf3 measurements against the target host.
func ProbeEnvironment(ctx context.Context, targetHost string, envName string, iface string) (*EnvironmentProfile, error) {
	profile := &EnvironmentProfile{
		Environment: envName,
		TargetHost:  targetHost,
		Timestamp:   time.Now(),
	}

	// 1. Ping probe (10 packets)
	pingOut, err := runCommand(ctx, "ping", "-c", "10", "-i", "0.2", targetHost)
	if err == nil {
		parsePingOutput(pingOut, profile)
	}

	// 2. Wireless RSSI check if wireless interface specified
	if iface != "" && envName == "wireless" {
		rssiOut, err := runCommand(ctx, "iw", "dev", iface, "link")
		if err == nil {
			profile.RSSI = extractRSSI(rssiOut)
		}
	}

	// 3. iperf3 TCP throughput (optional/if iperf3 server reachable)
	tcpOut, err := runCommand(ctx, "iperf3", "-c", targetHost, "-t", "3", "-J")
	if err == nil {
		profile.ThroughputTCP = parseIperf3TCP(tcpOut)
	}

	// 4. iperf3 UDP bandwidth and jitter
	udpOut, err := runCommand(ctx, "iperf3", "-c", targetHost, "-u", "-b", "50M", "-t", "3", "-J")
	if err == nil {
		profile.BandwidthUDP, profile.JitterMs = parseIperf3UDP(udpOut)
	}

	return profile, nil
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("cmd %s %s failed: %w (stderr: %s)", name, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}

func parsePingOutput(out string, p *EnvironmentProfile) {
	// Example line: rtt min/avg/max/mdev = 0.035/0.051/0.082/0.015 ms
	rttRegex := regexp.MustCompile(`rtt min/avg/max/mdev = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+) ms`)
	matches := rttRegex.FindStringSubmatch(out)
	if len(matches) == 5 {
		p.RTTMinMs, _ = strconv.ParseFloat(matches[1], 64)
		p.RTTAvgMs, _ = strconv.ParseFloat(matches[2], 64)
		p.RTTMaxMs, _ = strconv.ParseFloat(matches[3], 64)
		p.JitterMs, _ = strconv.ParseFloat(matches[4], 64)
	}

	// Example line: 10 packets transmitted, 10 received, 0% packet loss
	lossRegex := regexp.MustCompile(`([\d\.]+)% packet loss`)
	lossMatch := lossRegex.FindStringSubmatch(out)
	if len(lossMatch) == 2 {
		p.PacketLossPct, _ = strconv.ParseFloat(lossMatch[1], 64)
	}
}

func extractRSSI(out string) string {
	// Example line: signal: -55 dBm
	re := regexp.MustCompile(`signal:\s*(-?\d+\s*dBm)`)
	matches := re.FindStringSubmatch(out)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

func parseIperf3TCP(jsonStr string) float64 {
	var res struct {
		End struct {
			SumReceived struct {
				BitsPerSecond float64 `json:"bits_per_second"`
			} `json:"sum_received"`
		} `json:"end"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &res); err == nil && res.End.SumReceived.BitsPerSecond > 0 {
		return res.End.SumReceived.BitsPerSecond / 1e6
	}
	return 0.0
}

func parseIperf3UDP(jsonStr string) (float64, float64) {
	var res struct {
		End struct {
			Sum struct {
				BitsPerSecond float64 `json:"bits_per_second"`
				JitterMs      float64 `json:"jitter_ms"`
			} `json:"sum"`
		} `json:"end"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &res); err == nil {
		return res.End.Sum.BitsPerSecond / 1e6, res.End.Sum.JitterMs
	}
	return 0.0, 0.0
}
