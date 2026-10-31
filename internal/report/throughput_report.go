package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"qtbench/internal/benchmark"
	"qtbench/internal/packet"
)

// ScenarioResult holds aggregated metrics for one (scenario, protocol, qos) combination.
type ScenarioResult struct {
	Scenario        string  `json:"scenario"`
	Protocol        string  `json:"protocol"`
	QoS             byte    `json:"qos"`
	Iterations      int     `json:"iterations"`
	AvgSent         float64 `json:"avg_sent"`
	AvgRecv         float64 `json:"avg_recv"`
	DeliveryPct     float64 `json:"delivery_pct"`
	LatencyMeanMs   float64 `json:"latency_mean_ms"`
	LatencyMedianMs float64 `json:"latency_median_ms"`
	LatencyP95Ms    float64 `json:"latency_p95_ms"`
	LatencyP99Ms    float64 `json:"latency_p99_ms"`
	LatencyStdDevMs float64 `json:"latency_stddev_ms"`
	ThroughputMbps  float64 `json:"throughput_mbps"`
	PacketCount     int     `json:"packet_count"`
	OverheadPct     float64 `json:"overhead_pct"`
}

// ComparisonRow represents a comparison between TCP and QUIC for Table 11.
type ComparisonRow struct {
	Scenario        string  `json:"scenario"`
	LatencyWinner   string  `json:"latency_winner"`
	LatencyDeltaPct float64 `json:"latency_delta_pct"`
	ThptWinner      string  `json:"thpt_winner"`
	ThptDeltaPct    float64 `json:"thpt_delta_pct"`
}

// ThroughputReport is the full Experiment B report.
type ThroughputReport struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Environment string           `json:"environment"`
	Results     []ScenarioResult `json:"results"`
	Comparisons []ComparisonRow  `json:"comparisons"`
}

// RunThroughputReport reads the exp_b_runs CSV and delivery files, then computes all metrics.
func RunThroughputReport(runsCsvPath string, environment string, brokerIP string, tcpPort int, quicPort int, keylogPath string) (*ThroughputReport, error) {
	f, err := os.Open(runsCsvPath)
	if err != nil {
		return nil, fmt.Errorf("open runs csv: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse runs csv: %w", err)
	}

	type trialKey struct {
		scenario string
		protocol string
		qos      byte
	}

	type trialData struct {
		records []benchmark.MessageRunRecord
	}

	grouped := make(map[trialKey]*trialData)

	// CSV header: timestamp,iteration,scenario,protocol,qos,sent,recv,first_send_ns,last_ack_ns,total_payload_bytes,pcap_path,deliveries_path,success,error
	for i, row := range rows {
		if i == 0 {
			continue
		}
		if len(row) < 13 {
			continue
		}

		// Success check is in row[12] if deliveries_path was included, or row[11] if old format
		successIdx := 12
		delivIdx := 11
		if len(row) == 13 && (row[12] == "true" || row[12] == "false") {
			successIdx = 12
			delivIdx = 11
		} else if len(row) == 14 {
			successIdx = 12
			delivIdx = 11
		} else if len(row) == 12 {
			successIdx = 11
			delivIdx = -1
		}

		if row[successIdx] != "true" {
			continue
		}

		var iter, qosByte, sent, recv int
		var firstNs, lastNs, totalPayBytes int64
		fmt.Sscanf(row[1], "%d", &iter)
		fmt.Sscanf(row[4], "%d", &qosByte)
		fmt.Sscanf(row[5], "%d", &sent)
		fmt.Sscanf(row[6], "%d", &recv)
		fmt.Sscanf(row[7], "%d", &firstNs)
		fmt.Sscanf(row[8], "%d", &lastNs)
		fmt.Sscanf(row[9], "%d", &totalPayBytes)
		pcapPath := row[10]
		delivPath := ""
		if delivIdx > 0 && delivIdx < len(row) {
			delivPath = row[delivIdx]
		}
		scenario := row[2]
		proto := row[3]
		ts, _ := time.Parse("2006-01-02T15:04:05.000000000Z07:00", row[0])

		k := trialKey{scenario: scenario, protocol: proto, qos: byte(qosByte)}
		if grouped[k] == nil {
			grouped[k] = &trialData{}
		}

		// Read latencies from deliveries file if present
		latencies := readLatenciesFromFile(delivPath)

		rec := benchmark.MessageRunRecord{
			Iteration:         iter,
			Scenario:          scenario,
			Protocol:          proto,
			QoS:               byte(qosByte),
			SentCount:         sent,
			RecvCount:         recv,
			FirstSendNs:       firstNs,
			LastAckNs:         lastNs,
			LatenciesMs:       latencies,
			TotalPayloadBytes: totalPayBytes,
			PcapPath:          pcapPath,
			DeliveriesPath:    delivPath,
			Success:           true,
			Timestamp:         ts,
		}
		grouped[k].records = append(grouped[k].records, rec)
	}

	report := &ThroughputReport{
		GeneratedAt: time.Now(),
		Environment: environment,
	}

	keys := make([]trialKey, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].scenario != keys[j].scenario {
			return keys[i].scenario < keys[j].scenario
		}
		if keys[i].protocol != keys[j].protocol {
			return keys[i].protocol < keys[j].protocol
		}
		return keys[i].qos < keys[j].qos
	})

	for _, k := range keys {
		data := grouped[k]
		sr := computeScenarioResult(k.scenario, k.protocol, k.qos, data.records, brokerIP, tcpPort, quicPort, keylogPath)
		report.Results = append(report.Results, sr)
	}

	// Compute Table 11 comparisons
	report.Comparisons = buildComparisons(report.Results)

	return report, nil
}

func readLatenciesFromFile(path string) []float64 {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		return nil
	}

	var res []float64
	for i, row := range rows {
		if i == 0 || len(row) < 6 {
			continue
		}
		val, parseErr := strconv.ParseFloat(row[5], 64)
		if parseErr == nil {
			res = append(res, val)
		}
	}
	return res
}

func computeScenarioResult(scenario string, proto string, qos byte, records []benchmark.MessageRunRecord, brokerIP string, tcpPort int, quicPort int, keylogPath string) ScenarioResult {
	sr := ScenarioResult{
		Scenario:   scenario,
		Protocol:   proto,
		QoS:        qos,
		Iterations: len(records),
	}

	var allLatencies []float64
	var totalSent, totalRecv int
	var totalPayBytes int64
	var totalDurationSec float64

	for _, rec := range records {
		totalSent += rec.SentCount
		totalRecv += rec.RecvCount
		totalPayBytes += rec.TotalPayloadBytes
		if rec.FirstSendNs > 0 && rec.LastAckNs > rec.FirstSendNs {
			totalDurationSec += float64(rec.LastAckNs-rec.FirstSendNs) / 1e9
		}
		allLatencies = append(allLatencies, rec.LatenciesMs...)
	}

	n := len(records)
	if n > 0 {
		sr.AvgSent = float64(totalSent) / float64(n)
		sr.AvgRecv = float64(totalRecv) / float64(n)
	}
	if totalSent > 0 {
		sr.DeliveryPct = float64(totalRecv) / float64(totalSent) * 100.0
	}

	stats := benchmark.ComputeStats(allLatencies, totalPayBytes, totalDurationSec, totalSent)
	sr.LatencyMeanMs = stats.Mean
	sr.LatencyMedianMs = stats.Median
	sr.LatencyP95Ms = stats.P95
	sr.LatencyP99Ms = stats.P99
	sr.LatencyStdDevMs = stats.StdDev
	sr.ThroughputMbps = stats.Throughput

	// Task 4.3: Packet count & overhead from pcap
	var totalPcapBytes int64
	var totalPackets int
	var pcapCount int
	port := quicPort
	if proto == benchmark.ProtocolTCPTLS {
		port = tcpPort
	}
	for _, rec := range records {
		if rec.PcapPath == "" {
			continue
		}
		pktStats, err := packet.CountHandshakePackets(rec.PcapPath, proto, brokerIP, port, keylogPath)
		if err == nil && pktStats.Success {
			totalPcapBytes += pktStats.TotalBytes
			totalPackets += pktStats.PacketCount
			pcapCount++
		}
	}

	if pcapCount > 0 {
		sr.PacketCount = totalPackets / pcapCount
	}
	if totalPayBytes > 0 && pcapCount > 0 {
		sr.OverheadPct = (float64(totalPcapBytes) - float64(totalPayBytes)) / float64(totalPayBytes) * 100.0
	}

	return sr
}

func buildComparisons(results []ScenarioResult) []ComparisonRow {
	byScenario := make(map[string]map[string]ScenarioResult)
	for _, sr := range results {
		if byScenario[sr.Scenario] == nil {
			byScenario[sr.Scenario] = make(map[string]ScenarioResult)
		}
		byScenario[sr.Scenario][sr.Protocol] = sr
	}

	var rows []ComparisonRow
	seenScenarios := make(map[string]bool)
	var scenarios []string
	for _, sc := range benchmark.AllScenarios {
		if !seenScenarios[sc] {
			seenScenarios[sc] = true
			scenarios = append(scenarios, sc)
		}
	}
	for _, sr := range results {
		if !seenScenarios[sr.Scenario] {
			seenScenarios[sr.Scenario] = true
			scenarios = append(scenarios, sr.Scenario)
		}
	}

	for _, sc := range scenarios {
		m := byScenario[sc]
		if m == nil {
			continue
		}
		tcp, hasTCP := m[benchmark.ProtocolTCPTLS]
		quic, hasQUIC := m[benchmark.ProtocolQUIC]
		if !hasTCP || !hasQUIC {
			continue
		}

		// Latency comparison (lower is better)
		latWinner := "QUIC"
		var latDelta float64
		if tcp.LatencyP95Ms > 0 && quic.LatencyP95Ms > 0 {
			if quic.LatencyP95Ms < tcp.LatencyP95Ms {
				latWinner = "QUIC"
				latDelta = ((tcp.LatencyP95Ms - quic.LatencyP95Ms) / tcp.LatencyP95Ms) * 100.0
			} else {
				latWinner = "TCP"
				latDelta = ((quic.LatencyP95Ms - tcp.LatencyP95Ms) / quic.LatencyP95Ms) * 100.0
			}
		}

		// Throughput comparison (higher is better)
		thptWinner := "QUIC"
		var thptDelta float64
		if quic.ThroughputMbps > tcp.ThroughputMbps {
			thptWinner = "QUIC"
			if tcp.ThroughputMbps > 0 {
				thptDelta = ((quic.ThroughputMbps - tcp.ThroughputMbps) / tcp.ThroughputMbps) * 100.0
			}
		} else {
			thptWinner = "TCP"
			if quic.ThroughputMbps > 0 {
				thptDelta = ((tcp.ThroughputMbps - quic.ThroughputMbps) / quic.ThroughputMbps) * 100.0
			}
		}

		rows = append(rows, ComparisonRow{
			Scenario:        sc,
			LatencyWinner:   latWinner,
			LatencyDeltaPct: latDelta,
			ThptWinner:      thptWinner,
			ThptDeltaPct:    thptDelta,
		})
	}

	return rows
}

// ExportThroughputTableMarkdown writes Tables 9/10/11 to a Markdown file.
func ExportThroughputTableMarkdown(report *ThroughputReport, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	outPath := filepath.Join(outputDir, fmt.Sprintf("exp_b_tables_%s.md", report.Environment))
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := func(format string, args ...any) {
		fmt.Fprintf(f, format+"\n", args...)
	}

	tableName := "Table 8: Ket qua moi truong co day (Wired Environment)"
	if strings.Contains(strings.ToLower(report.Environment), "wireless") {
		tableName = "Table 9: Ket qua moi truong khong day (Wireless Environment)"
	}

	w("# Experiment B - Throughput & Degradation Results: %s", report.Environment)
	w("Generated: %s", report.GeneratedAt.Format(time.RFC3339))
	w("")

	// Primary Table 9 or Table 10 from docs/Ke_hoach_thu_nghiem_MQTT_QUIC.md
	w("## %s", tableName)
	w("")
	w("| Truong hop | Giao thuc | Do tre TB +- sigma (ms) | Do tre p95 (ms) | Thong luong (Mbps) | Ty le giao (%%) | So goi | Overhead (%%) |")
	w("| --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, sr := range report.Results {
		protoLabel := "TCP"
		if sr.Protocol == benchmark.ProtocolQUIC {
			protoLabel = "QUIC"
		}
		overheadStr := "-"
		if sr.OverheadPct != 0 {
			overheadStr = fmt.Sprintf("%.2f", sr.OverheadPct)
		}
		w("| %s | %s | %.2f +- %.2f | %.2f | %.4f | %.1f | %d | %s |",
			sr.Scenario, protoLabel,
			sr.LatencyMeanMs, sr.LatencyStdDevMs,
			sr.LatencyP95Ms, sr.ThroughputMbps,
			sr.DeliveryPct, sr.PacketCount, overheadStr)
	}
	w("")

	// Table 10: Best protocol comparison table
	w("## Table 10: Giao thuc tot hon theo truong hop va chi so (Environment: %s)", report.Environment)
	w("")
	w("| Truong hop | Do tre p95 Tot hon | Delta p95 (%%) | Thong luong Tot hon | Delta Thpt (%%) |")
	w("| --- | --- | --- | --- | --- |")
	for _, cmp := range report.Comparisons {
		w("| %s | %s | %.2f%% | %s | %.2f%% |",
			cmp.Scenario, cmp.LatencyWinner, cmp.LatencyDeltaPct,
			cmp.ThptWinner, cmp.ThptDeltaPct)
	}
	w("")

	// Detailed breakdown table
	w("## Message Latency Percentiles Breakdown (ms)")
	w("")
	w("| Scenario | Protocol | QoS | Iterations | Mean | Median | P95 | P99 | StdDev |")
	w("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, sr := range report.Results {
		w("| %s | %s | %d | %d | %.2f | %.2f | %.2f | %.2f | %.2f |",
			sr.Scenario, sr.Protocol, sr.QoS, sr.Iterations,
			sr.LatencyMeanMs, sr.LatencyMedianMs, sr.LatencyP95Ms, sr.LatencyP99Ms, sr.LatencyStdDevMs)
	}
	w("")

	w("## Ghi chu")
	w("- Do tre duoc tinh giua t_send (publisher) va t_recv (subscriber) tren cung May 1.")
	w("- Do tre p95 duoc tinh theo phuong phap nearest-rank tren toan bo tap tin nhan duoc.")
	w("- Thong luong = 8 * B_received / (T_transfer * 10^6) (Mbps).")
	w("- Ty le giao (%%) tinh tren so tin nhan duy nhat (khong trung lap) nhan duoc.")
	w("- Overhead (%%) = (wire_bytes_pcap - payload_bytes) / payload_bytes * 100%%.")

	return nil
}

// ExportThroughputJSON writes the full report as JSON.
func ExportThroughputJSON(report *ThroughputReport, outputDir string) error {
	outPath := filepath.Join(outputDir, fmt.Sprintf("exp_b_report_%s.json", report.Environment))
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// PrintThroughputConsole prints a concise summary to stdout.
func PrintThroughputConsole(report *ThroughputReport) {
	fmt.Printf("\n=== Experiment B Report | Environment: %s ===\n\n", strings.ToUpper(report.Environment))
	for _, sr := range report.Results {
		fmt.Printf("[%s | %s] Deliv:%.1f%%  Latency:%.2f+-%.2fms  P95:%.2fms  P99:%.2fms  Thpt:%.4fMbps  Pkts:%d  Overhead:%.2f%%\n",
			sr.Scenario, strings.ToUpper(sr.Protocol),
			sr.DeliveryPct, sr.LatencyMeanMs, sr.LatencyStdDevMs,
			sr.LatencyP95Ms, sr.LatencyP99Ms,
			sr.ThroughputMbps, sr.PacketCount, sr.OverheadPct)
	}
	if len(report.Comparisons) > 0 {
		fmt.Printf("\n--- Table 11 Head-to-Head Comparison ---\n")
		for _, cmp := range report.Comparisons {
			fmt.Printf("Scenario %s: P95 Winner: %s (Δ%.1f%%) | Thpt Winner: %s (Δ%.1f%%)\n",
				cmp.Scenario, cmp.LatencyWinner, cmp.LatencyDeltaPct,
				cmp.ThptWinner, cmp.ThptDeltaPct)
		}
	}
	fmt.Println()
}
