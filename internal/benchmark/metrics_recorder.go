package benchmark

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// SummaryStats contains aggregated statistical figures for a metrics series.
type SummaryStats struct {
	Count       int     `json:"count"`
	Mean        float64 `json:"mean"`
	StdDev      float64 `json:"std_dev"`
	Min         float64 `json:"min"`
	Median      float64 `json:"median"`
	P95         float64 `json:"p95"`
	P99         float64 `json:"p99"`
	Max         float64 `json:"max"`
	Throughput  float64 `json:"throughput_mbps"`
	DeliveryPct float64 `json:"delivery_pct"`
}

// ComputeStats calculates summary statistics including P95 and P99 using nearest-rank.
func ComputeStats(values []float64, totalBytesReceived int64, transferDurationSec float64, totalSentCount int) SummaryStats {
	n := len(values)
	if n == 0 {
		return SummaryStats{}
	}

	sorted := make([]float64, n)
	copy(sorted, values)
	sort.Float64s(sorted)

	var sum float64
	for _, v := range sorted {
		sum += v
	}
	mean := sum / float64(n)

	var varianceSum float64
	for _, v := range sorted {
		varianceSum += (v - mean) * (v - mean)
	}
	stdDev := math.Sqrt(varianceSum / float64(n))

	nearestRank := func(p float64) float64 {
		if n == 1 {
			return sorted[0]
		}
		// Nearest-rank method: index = ceil(p * n) - 1
		idx := int(math.Ceil(p*float64(n))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= n {
			idx = n - 1
		}
		return sorted[idx]
	}

	throughput := 0.0
	if transferDurationSec > 0 {
		// Formula: 8 * B_received / (T_transfer * 10^6)
		throughput = (8.0 * float64(totalBytesReceived)) / (transferDurationSec * 1e6)
	}

	deliveryPct := 0.0
	if totalSentCount > 0 {
		deliveryPct = (float64(n) / float64(totalSentCount)) * 100.0
	}

	return SummaryStats{
		Count:       n,
		Mean:        mean,
		StdDev:      stdDev,
		Min:         sorted[0],
		Median:      nearestRank(0.50),
		P95:         nearestRank(0.95),
		P99:         nearestRank(0.99),
		Max:         sorted[n-1],
		Throughput:  throughput,
		DeliveryPct: deliveryPct,
	}
}

// MetricsRecorder manages logging and CSV storage of benchmark measurements.
type MetricsRecorder struct {
	mu sync.Mutex

	handshakeFile *os.File
	handshakeCSV  *csv.Writer

	pubFile *os.File
	pubCSV  *csv.Writer

	subFile *os.File
	subCSV  *csv.Writer
}

// NewMetricsRecorder opens CSV files in the destination directory and writes headers.
func NewMetricsRecorder(resultsDir string, runID string) (*MetricsRecorder, error) {
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create results dir %s: %w", resultsDir, err)
	}

	rec := &MetricsRecorder{}

	// Handshake CSV
	hsPath := filepath.Join(resultsDir, fmt.Sprintf("handshake_%s.csv", runID))
	hf, err := os.OpenFile(hsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	rec.handshakeFile = hf
	rec.handshakeCSV = csv.NewWriter(hf)
	_ = rec.handshakeCSV.Write([]string{"timestamp", "proto", "broker", "duration_ms", "success", "error"})
	rec.handshakeCSV.Flush()

	// Publisher CSV
	pubPath := filepath.Join(resultsDir, fmt.Sprintf("publisher_%s.csv", runID))
	pf, err := os.OpenFile(pubPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		rec.Close()
		return nil, err
	}
	rec.pubFile = pf
	rec.pubCSV = csv.NewWriter(pf)
	_ = rec.pubCSV.Write([]string{"timestamp", "seq", "qos", "send_ns", "ack_ns", "duration_ms", "success", "error"})
	rec.pubCSV.Flush()

	// Subscriber CSV
	subPath := filepath.Join(resultsDir, fmt.Sprintf("subscriber_%s.csv", runID))
	sf, err := os.OpenFile(subPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		rec.Close()
		return nil, err
	}
	rec.subFile = sf
	rec.subCSV = csv.NewWriter(sf)
	_ = rec.subCSV.Write([]string{"timestamp", "seq", "qos", "send_ns", "recv_ns", "latency_ms", "payload_len"})
	rec.subCSV.Flush()

	return rec, nil
}

// RecordHandshake logs a connection establishment event to CSV.
func (r *MetricsRecorder) RecordHandshake(res *HandshakeResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handshakeCSV == nil {
		return
	}

	_ = r.handshakeCSV.Write([]string{
		res.Timestamp.Format(time.RFC3339Nano),
		res.Protocol,
		res.BrokerAddr,
		fmt.Sprintf("%.4f", res.DurationMs),
		fmt.Sprintf("%t", res.Success),
		res.Error,
	})
	r.handshakeCSV.Flush()
}

// RecordPublish logs a publish event to CSV.
func (r *MetricsRecorder) RecordPublish(m *PublishMetric) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pubCSV == nil {
		return
	}

	_ = r.pubCSV.Write([]string{
		m.Timestamp.Format(time.RFC3339Nano),
		fmt.Sprintf("%d", m.Seq),
		fmt.Sprintf("%d", m.QoS),
		fmt.Sprintf("%d", m.SendNs),
		fmt.Sprintf("%d", m.AckNs),
		fmt.Sprintf("%.4f", m.DurationMs),
		fmt.Sprintf("%t", m.Success),
		m.Error,
	})
	r.pubCSV.Flush()
}

// RecordDelivery logs a received message event to CSV.
func (r *MetricsRecorder) RecordDelivery(d *DeliveryMetric) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.subCSV == nil {
		return
	}

	_ = r.subCSV.Write([]string{
		d.Timestamp.Format(time.RFC3339Nano),
		fmt.Sprintf("%d", d.Seq),
		fmt.Sprintf("%d", d.QoS),
		fmt.Sprintf("%d", d.SendNs),
		fmt.Sprintf("%d", d.RecvNs),
		fmt.Sprintf("%.4f", d.LatencyMs),
		fmt.Sprintf("%d", d.PayloadLen),
	})
	r.subCSV.Flush()
}

// Close flushes buffers and closes all underlying CSV file handlers.
func (r *MetricsRecorder) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.handshakeCSV != nil {
		r.handshakeCSV.Flush()
	}
	if r.handshakeFile != nil {
		_ = r.handshakeFile.Close()
		r.handshakeFile = nil
	}

	if r.pubCSV != nil {
		r.pubCSV.Flush()
	}
	if r.pubFile != nil {
		_ = r.pubFile.Close()
		r.pubFile = nil
	}

	if r.subCSV != nil {
		r.subCSV.Flush()
	}
	if r.subFile != nil {
		_ = r.subFile.Close()
		r.subFile = nil
	}
}
