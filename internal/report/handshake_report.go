package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"qtbench/internal/packet"
)

// HandshakeTrial aggregates all metrics for one complete trial (timing + packet stats).
type HandshakeTrial struct {
	Iteration     int
	Protocol      string
	Environment   string
	Timestamp     time.Time
	BaselineRTTMs float64
	PcapPath      string

	// From pcap timing analysis
	AppDurationMs  float64
	PcapDurationMs float64
	Round1Ms       float64
	Round2Ms       float64
	Round3Ms       float64 // -1 if N/A
	PacketCount    int
	TotalBytes     int64
	TimingSuccess  bool
	PacketSuccess  bool
}

// HandshakeAnalysisReport holds the full set of results for Experiment A across environments.
type HandshakeAnalysisReport struct {
	GeneratedAt time.Time
	Environment string
	TCPTrials   []HandshakeTrial
	QUICTrials  []HandshakeTrial
}

// RunHandshakeReport loads trial CSV, re-analyzes pcaps, and returns a consolidated report.
func RunHandshakeReport(runsCsvPath string, environment string, brokerIP string, tcpPort int, quicPort int, keylogPath string) (*HandshakeAnalysisReport, error) {
	f, err := os.Open(runsCsvPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open runs csv: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse runs csv: %w", err)
	}

	report := &HandshakeAnalysisReport{
		GeneratedAt: time.Now(),
		Environment: environment,
	}

	// CSV header: timestamp,iteration,protocol,broker_addr,baseline_rtt_ms,app_duration_ms,pcap_path,success,error
	for i, row := range rows {
		if i == 0 { // skip header
			continue
		}
		if len(row) < 8 {
			continue
		}

		successStr := row[7]
		if successStr != "true" {
			continue
		}

		var iteration int
		fmt.Sscanf(row[1], "%d", &iteration)
		proto := row[2]
		var baselineRTT, appDuration float64
		fmt.Sscanf(row[4], "%f", &baselineRTT)
		fmt.Sscanf(row[5], "%f", &appDuration)
		pcapPath := row[6]
		ts, _ := time.Parse(time.RFC3339Nano, row[0])

		trial := HandshakeTrial{
			Iteration:     iteration,
			Protocol:      proto,
			Environment:   environment,
			Timestamp:     ts,
			BaselineRTTMs: baselineRTT,
			AppDurationMs: appDuration,
			PcapPath:      pcapPath,
		}

		// Analyze pcap timing
		timing, timingErr := packet.AnalyzeHandshakePCAP(pcapPath, proto, keylogPath)
		if timingErr == nil && timing.Success {
			trial.TimingSuccess = true
			trial.PcapDurationMs = timing.TotalDurationMs
			trial.Round1Ms = timing.Round1Ms
			trial.Round2Ms = timing.Round2Ms
			trial.Round3Ms = timing.Round3Ms
		}

		// Count packets and bytes
		port := quicPort
		if proto == "tcp-tls" {
			port = tcpPort
		}
		pktStats, pktErr := packet.CountHandshakePackets(pcapPath, proto, brokerIP, port, keylogPath)
		if pktErr == nil && pktStats.Success {
			trial.PacketSuccess = true
			trial.PacketCount = pktStats.PacketCount
			trial.TotalBytes = pktStats.TotalBytes
		}

		if proto == "tcp-tls" {
			report.TCPTrials = append(report.TCPTrials, trial)
		} else {
			report.QUICTrials = append(report.QUICTrials, trial)
		}
	}

	return report, nil
}

// stat helpers
func median(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)
	n := len(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}

func stdDev(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	var variance float64
	for _, v := range vals {
		variance += (v - mean) * (v - mean)
	}
	return math.Sqrt(variance / float64(len(vals)))
}

type summaryRow struct {
	label      string
	durationMs float64
	packets    int
	bytes      int64
}

// ExportTableMarkdown writes a Markdown version of Tables 5/6/7 to the results directory.
func ExportTableMarkdown(report *HandshakeAnalysisReport, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	outPath := filepath.Join(outputDir, fmt.Sprintf("exp_a_tables_%s.md", report.Environment))
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := func(format string, args ...any) {
		fmt.Fprintf(f, format+"\n", args...)
	}

	w("# Experiment A - Handshake Results: %s", report.Environment)
	w("Generated: %s", report.GeneratedAt.Format(time.RFC3339))
	w("")

	// Table 5: Client-side timing + packet stats
	w("## Table 5: Results from Client Machine (tshark on Machine 1)")
	w("")
	w("| Trial | Protocol | Total Duration (ms) | Packets | Bytes | Baseline RTT (ms) | App Duration (ms) |")
	w("|-------|----------|---------------------|---------|-------|-------------------|-------------------|")

	allTrials := append(report.TCPTrials, report.QUICTrials...)
	sort.Slice(allTrials, func(i, j int) bool {
		if allTrials[i].Iteration != allTrials[j].Iteration {
			return allTrials[i].Iteration < allTrials[j].Iteration
		}
		return allTrials[i].Protocol < allTrials[j].Protocol
	})

	for _, t := range allTrials {
		durationStr := "-"
		if t.TimingSuccess {
			durationStr = fmt.Sprintf("%.2f", t.PcapDurationMs)
		}
		pktStr := "-"
		bytesStr := "-"
		if t.PacketSuccess {
			pktStr = fmt.Sprintf("%d", t.PacketCount)
			bytesStr = fmt.Sprintf("%d", t.TotalBytes)
		}
		w("| %d | %s | %s | %s | %s | %.2f | %.2f |",
			t.Iteration, t.Protocol, durationStr, pktStr, bytesStr, t.BaselineRTTMs, t.AppDurationMs)
	}

	// Summary rows (median + stddev)
	writeProtoSummary := func(label string, trials []HandshakeTrial) {
		var durations, appDurations []float64
		var pkts []int
		var bytes []int64
		for _, t := range trials {
			if t.TimingSuccess {
				durations = append(durations, t.PcapDurationMs)
			}
			appDurations = append(appDurations, t.AppDurationMs)
			if t.PacketSuccess {
				pkts = append(pkts, t.PacketCount)
				bytes = append(bytes, t.TotalBytes)
			}
		}

		medDur := "-"
		stdDur := "-"
		if len(durations) > 0 {
			medDur = fmt.Sprintf("%.2f", median(durations))
			stdDur = fmt.Sprintf("%.2f", stdDev(durations))
		}

		medPkt := "-"
		medBytes := "-"
		if len(pkts) > 0 {
			var pktF []float64
			var bytF []float64
			for _, p := range pkts {
				pktF = append(pktF, float64(p))
			}
			for _, b := range bytes {
				bytF = append(bytF, float64(b))
			}
			medPkt = fmt.Sprintf("%.0f", median(pktF))
			medBytes = fmt.Sprintf("%.0f", median(bytF))
		}

		w("| Median | %s | %s | %s | %s | - | %.2f |", label, medDur, medPkt, medBytes, median(appDurations))
		w("| StdDev | %s | %s | - | - | - | %.2f |", label, stdDur, stdDev(appDurations))
	}

	writeProtoSummary("TCP/TLS", report.TCPTrials)
	writeProtoSummary("QUIC", report.QUICTrials)
	w("")

	// Table 6: Per-round RTT breakdown
	w("## Table 6: Per-RTT-Round Timings from Client (ms)")
	w("")
	w("| Trial | Protocol | Round 1 (ms) | Round 2 (ms) | Round 3 (ms) |")
	w("|-------|----------|-------------|-------------|-------------|")

	for _, t := range allTrials {
		if !t.TimingSuccess {
			continue
		}
		r1 := fmt.Sprintf("%.2f", t.Round1Ms)
		r2 := fmt.Sprintf("%.2f", t.Round2Ms)
		r3 := fmt.Sprintf("%.2f", t.Round3Ms)
		if t.Protocol == "quic" {
			r3 = "-"
		}
		w("| %d | %s | %s | %s | %s |", t.Iteration, t.Protocol, r1, r2, r3)
	}

	// Median summary for Table 7
	writeRoundSummary := func(label string, trials []HandshakeTrial) {
		var r1, r2, r3 []float64
		for _, t := range trials {
			if !t.TimingSuccess {
				continue
			}
			if t.Round1Ms > 0 {
				r1 = append(r1, t.Round1Ms)
			}
			if t.Round2Ms > 0 {
				r2 = append(r2, t.Round2Ms)
			}
			if t.Round3Ms > 0 {
				r3 = append(r3, t.Round3Ms)
			}
		}
		r1s, r2s, r3s := "-", "-", "-"
		if len(r1) > 0 {
			r1s = fmt.Sprintf("%.2f", median(r1))
		}
		if len(r2) > 0 {
			r2s = fmt.Sprintf("%.2f", median(r2))
		}
		if len(r3) > 0 {
			r3s = fmt.Sprintf("%.2f", median(r3))
		} else if label == "QUIC" {
			r3s = "-"
		}
		w("| Median | %s | %s | %s | %s |", label, r1s, r2s, r3s)
	}

	writeRoundSummary("TCP/TLS", report.TCPTrials)
	writeRoundSummary("QUIC", report.QUICTrials)
	w("")
	w("> Round 1: TCP=SYN-SYNACK, QUIC=Initial-ServerHandshake")
	w("> Round 2: TCP=ClientHello-ServerFinished, QUIC=CONNECT-CONNACK")
	w("> Round 3: TCP=CONNECT-CONNACK, QUIC=N/A (-)")
	w("")
	w("## Notes")
	w("- Timings extracted from tshark pcap on Machine 1 (publisher side)")
	w("- TLS session secrets exported via SSLKEYLOGFILE for MQTT message identification")
	w("- All connections are fresh 1-RTT (no session resumption / 0-RTT)")

	return nil
}

// ExportTableJSON serializes the full report as JSON alongside the Markdown.
func ExportTableJSON(report *HandshakeAnalysisReport, outputDir string) error {
	outPath := filepath.Join(outputDir, fmt.Sprintf("exp_a_report_%s.json", report.Environment))
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// PrintConsole prints a brief summary to stdout.
func PrintConsole(report *HandshakeAnalysisReport) {
	fmt.Printf("\n=== Experiment A Report | Environment: %s ===\n\n", strings.ToUpper(report.Environment))

	printProto := func(proto string, trials []HandshakeTrial) {
		var appMs, pcapMs, r1, r2, r3 []float64
		for _, t := range trials {
			appMs = append(appMs, t.AppDurationMs)
			if t.TimingSuccess {
				pcapMs = append(pcapMs, t.PcapDurationMs)
				if t.Round1Ms > 0 {
					r1 = append(r1, t.Round1Ms)
				}
				if t.Round2Ms > 0 {
					r2 = append(r2, t.Round2Ms)
				}
				if t.Round3Ms > 0 {
					r3 = append(r3, t.Round3Ms)
				}
			}
		}

		fmt.Printf("[%s] Trials: %d\n", proto, len(trials))
		if len(appMs) > 0 {
			fmt.Printf("  App Handshake (ms) - Median: %.2f  StdDev: %.2f\n", median(appMs), stdDev(appMs))
		}
		if len(pcapMs) > 0 {
			fmt.Printf("  PCAP Handshake (ms)- Median: %.2f  StdDev: %.2f\n", median(pcapMs), stdDev(pcapMs))
		}
		if len(r1) > 0 {
			fmt.Printf("  Round 1 (ms)       - Median: %.2f\n", median(r1))
		}
		if len(r2) > 0 {
			fmt.Printf("  Round 2 (ms)       - Median: %.2f\n", median(r2))
		}
		if len(r3) > 0 {
			fmt.Printf("  Round 3 (ms)       - Median: %.2f\n", median(r3))
		} else if proto == "QUIC" {
			fmt.Printf("  Round 3 (ms)       - N/A\n")
		}
		fmt.Println()
	}

	printProto("TCP/TLS", report.TCPTrials)
	printProto("QUIC", report.QUICTrials)
}
