// Command analyzexpa: post-run analysis tool for Experiment A.
// Reads the runs CSV produced by exparunner, re-analyzes every pcap file,
// and outputs Markdown Tables 6 and 7 + JSON report.
//
// Usage:
//
//	analyzexpa -runs <path/to/exp_a_handshake_runs.csv> \
//	           -env  <environment_label> \
//	           -broker-ip <IP> \
//	           -tcp-port  8883 \
//	           -quic-port 14567 \
//	           -keylog   <path/to/sslkeys.log> \
//	           -out      <output_dir>
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"qtbench/internal/report"
)

func main() {
	runsCsv := flag.String("runs", "", "Path to runs CSV produced by exparunner (required)")
	env := flag.String("env", "b0-baseline", "Environment label (e.g. b0-baseline, b1-loss1, ...)")
	brokerIP := flag.String("broker-ip", "127.0.0.1", "Broker IP address")
	tcpPort := flag.Int("tcp-port", 8883, "TCP/TLS broker port")
	quicPort := flag.Int("quic-port", 14567, "QUIC broker port")
	keylog := flag.String("keylog", "", "Path to SSLKEYLOGFILE for TLS decryption (optional)")
	outDir := flag.String("out", "results/exp_a", "Output directory for tables and JSON report")

	flag.Parse()

	if *runsCsv == "" {
		fmt.Fprintln(os.Stderr, "error: -runs flag is required")
		flag.Usage()
		os.Exit(1)
	}

	log.Printf("Loading runs from: %s", *runsCsv)
	log.Printf("Environment: %s | Broker: %s | TCP:%d | QUIC:%d", *env, *brokerIP, *tcpPort, *quicPort)

	r, err := report.RunHandshakeReport(*runsCsv, *env, *brokerIP, *tcpPort, *quicPort, *keylog)
	if err != nil {
		log.Fatalf("Failed to generate report: %v", err)
	}

	log.Printf("Trials loaded: TCP=%d QUIC=%d", len(r.TCPTrials), len(r.QUICTrials))

	// Print console summary
	report.PrintConsole(r)

	// Export Markdown tables
	if err := report.ExportTableMarkdown(r, *outDir); err != nil {
		log.Fatalf("Failed to export markdown: %v", err)
	}
	log.Printf("Markdown tables written to: %s", *outDir)

	// Export JSON report
	if err := report.ExportTableJSON(r, *outDir); err != nil {
		log.Fatalf("Failed to export JSON: %v", err)
	}
	log.Printf("JSON report written to: %s", *outDir)

	log.Println("Done.")
}
