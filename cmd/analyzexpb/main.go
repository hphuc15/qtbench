// Command analyzexpb: post-run analysis tool for Experiment B.
// Reads the runs CSV produced by expbrunner, individual delivery latency CSVs,
// pcap files for packet/overhead counts, and outputs Markdown Tables 9, 10, 11 + JSON report.
//
// Usage:
//
//	analyzexpb -runs <path/to/exp_b_runs.csv> \
//	           -env  wired \
//	           -broker-ip <IP> \
//	           -tcp-port  8883 \
//	           -quic-port 8884 \
//	           -keylog   <path/to/sslkeys.log> \
//	           -out      results/exp_b
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"qtbench/internal/report"
)

func main() {
	runsCsv := flag.String("runs", "", "Path to runs CSV produced by expbrunner (required)")
	env := flag.String("env", "wired", "Environment label (wired or wireless)")
	brokerIP := flag.String("broker-ip", "127.0.0.1", "Broker IP address")
	tcpPort := flag.Int("tcp-port", 8883, "TCP/TLS broker port")
	quicPort := flag.Int("quic-port", 8884, "QUIC broker port")
	keylog := flag.String("keylog", "", "Path to SSLKEYLOGFILE for TLS decryption (optional)")
	outDir := flag.String("out", "results/exp_b", "Output directory for tables and JSON report")

	flag.Parse()

	if *runsCsv == "" {
		fmt.Fprintln(os.Stderr, "error: -runs flag is required")
		flag.Usage()
		os.Exit(1)
	}

	log.Printf("Loading Experiment B runs from: %s", *runsCsv)
	log.Printf("Environment: %s | Broker: %s | TCP:%d | QUIC:%d", *env, *brokerIP, *tcpPort, *quicPort)

	r, err := report.RunThroughputReport(*runsCsv, *env, *brokerIP, *tcpPort, *quicPort, *keylog)
	if err != nil {
		log.Fatalf("Failed to generate throughput report: %v", err)
	}

	log.Printf("Scenario results computed: %d", len(r.Results))

	// Print console summary
	report.PrintThroughputConsole(r)

	// Export Markdown tables (Table 9 or 10, plus Table 11)
	if err := report.ExportThroughputTableMarkdown(r, *outDir); err != nil {
		log.Fatalf("Failed to export markdown: %v", err)
	}
	log.Printf("Markdown tables written to: %s", *outDir)

	// Export JSON report
	if err := report.ExportThroughputJSON(r, *outDir); err != nil {
		log.Fatalf("Failed to export JSON: %v", err)
	}
	log.Printf("JSON report written to: %s", *outDir)

	log.Println("Done.")
}
