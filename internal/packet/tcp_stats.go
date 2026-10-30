package packet

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TCPStats holds parsed connection telemetry from `ss -ti`.
type TCPStats struct {
	Timestamp   time.Time `json:"timestamp"`
	SrcAddr     string    `json:"src_addr"`
	DstAddr     string    `json:"dst_addr"`
	RTTMs       float64   `json:"rtt_ms"`
	RTOMs       float64   `json:"rto_ms"`
	Cwnd        int       `json:"cwnd"`
	Ssthresh    int       `json:"ssthresh"`
	MSS         int       `json:"mss"`
	Retransmits int       `json:"retransmits"`
	Unacked     int       `json:"unacked"`
}

// TCPStatsCollector periodically samples TCP socket statistics using `ss -ti`.
type TCPStatsCollector struct {
	port     int
	filePath string
	file     *os.File
	writer   *csv.Writer
	stopCh   chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
}

// NewTCPStatsCollector creates a collector recording socket metrics to the specified CSV file.
func NewTCPStatsCollector(port int, csvPath string) (*TCPStatsCollector, error) {
	dir := filepath.Dir(csvPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for tcp stats: %w", err)
	}

	f, err := os.OpenFile(csvPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open tcp stats file: %w", err)
	}

	w := csv.NewWriter(f)
	_ = w.Write([]string{"timestamp", "src", "dst", "rtt_ms", "rto_ms", "cwnd", "ssthresh", "mss", "retrans", "unacked"})
	w.Flush()

	return &TCPStatsCollector{
		port:     port,
		filePath: csvPath,
		file:     f,
		writer:   w,
		stopCh:   make(chan struct{}),
	}, nil
}

// Start begins periodic sampling at the given interval (e.g. 100ms).
func (c *TCPStatsCollector) Start(interval time.Duration) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				stats, err := c.SampleOnce()
				if err == nil && len(stats) > 0 {
					c.mu.Lock()
					for _, s := range stats {
						_ = c.writer.Write([]string{
							s.Timestamp.Format(time.RFC3339Nano),
							s.SrcAddr,
							s.DstAddr,
							fmt.Sprintf("%.3f", s.RTTMs),
							fmt.Sprintf("%.3f", s.RTOMs),
							strconv.Itoa(s.Cwnd),
							strconv.Itoa(s.Ssthresh),
							strconv.Itoa(s.MSS),
							strconv.Itoa(s.Retransmits),
							strconv.Itoa(s.Unacked),
						})
					}
					c.writer.Flush()
					c.mu.Unlock()
				}
			}
		}
	}()
}

// Stop stops the periodic sampler and flushes files.
func (c *TCPStatsCollector) Stop() {
	close(c.stopCh)
	c.wg.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writer != nil {
		c.writer.Flush()
	}
	if c.file != nil {
		_ = c.file.Close()
	}
}

// SampleOnce runs `ss -ti` and parses matching sockets.
func (c *TCPStatsCollector) SampleOnce() ([]TCPStats, error) {
	filter := fmt.Sprintf("( sport = :%d or dport = :%d )", c.port, c.port)
	cmd := exec.Command("ss", "-ti", filter)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	return parseSSOutput(stdout.String()), nil
}

func parseSSOutput(raw string) []TCPStats {
	lines := strings.Split(raw, "\n")
	var results []TCPStats
	now := time.Now()

	// Regex extractors for ss fields
	rttRegex := regexp.MustCompile(`rtt:([\d\.]+)/([\d\.]+)`)
	rtoRegex := regexp.MustCompile(`rto:([\d\.]+)`)
	cwndRegex := regexp.MustCompile(`cwnd:(\d+)`)
	ssthreshRegex := regexp.MustCompile(`ssthresh:(\d+)`)
	mssRegex := regexp.MustCompile(`mss:(\d+)`)
	retransRegex := regexp.MustCompile(`retrans:(\d+)/(\d+)`)
	unackedRegex := regexp.MustCompile(`unacked:(\d+)`)

	for i := 0; i < len(lines)-1; i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "ESTAB") || strings.HasPrefix(line, "TIME-WAIT") || strings.HasPrefix(line, "CLOSE-WAIT") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				stat := TCPStats{
					Timestamp: now,
					SrcAddr:   fields[3],
					DstAddr:   fields[4],
				}

				// The next line contains the TCP internal telemetry
				if i+1 < len(lines) {
					infoLine := lines[i+1]
					if m := rttRegex.FindStringSubmatch(infoLine); len(m) >= 2 {
						stat.RTTMs, _ = strconv.ParseFloat(m[1], 64)
					}
					if m := rtoRegex.FindStringSubmatch(infoLine); len(m) >= 2 {
						stat.RTOMs, _ = strconv.ParseFloat(m[1], 64)
					}
					if m := cwndRegex.FindStringSubmatch(infoLine); len(m) >= 2 {
						stat.Cwnd, _ = strconv.Atoi(m[1])
					}
					if m := ssthreshRegex.FindStringSubmatch(infoLine); len(m) >= 2 {
						stat.Ssthresh, _ = strconv.Atoi(m[1])
					}
					if m := mssRegex.FindStringSubmatch(infoLine); len(m) >= 2 {
						stat.MSS, _ = strconv.Atoi(m[1])
					}
					if m := retransRegex.FindStringSubmatch(infoLine); len(m) >= 2 {
						stat.Retransmits, _ = strconv.Atoi(m[1])
					}
					if m := unackedRegex.FindStringSubmatch(infoLine); len(m) >= 2 {
						stat.Unacked, _ = strconv.Atoi(m[1])
					}
				}

				results = append(results, stat)
			}
		}
	}

	return results
}
