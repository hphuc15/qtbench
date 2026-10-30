package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"qtbench/internal/benchmark"
)

func main() {
	exp := flag.String("exp", "a", "Experiment to execute: 'a' (Handshake) or 'b' (Impaired conditions)")
	brokerHost := flag.String("broker", "127.0.0.1", "Broker IP address or hostname")
	tcpPort := flag.Int("tcp-port", 8883, "Broker TCP/TLS 1.3 port")
	quicPort := flag.Int("quic-port", 14567, "Broker QUIC port")
	envName := flag.String("env", "wired", "Network environment: 'wired' or 'wireless'")
	iterations := flag.Int("iterations", 3, "Number of trial iterations (N_A >= 3 for pilot, >= 30 recommended)")
	iface := flag.String("iface", "any", "Capture network interface for tshark")
	resultsDir := flag.String("results", "./results", "Destination directory for pcap and metrics")
	keylog := flag.String("keylog", "./results/sslkeylog.log", "Path to SSLKEYLOGFILE")
	insecure := flag.Bool("insecure", true, "Skip TLS verification")
	serverName := flag.String("servername", "localhost", "TLS SNI server name")
	cooldown := flag.Duration("cooldown", 1*time.Second, "Cooldown delay between trial runs")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nReceived interrupt signal, stopping gracefully...")
		cancel()
	}()

	switch *exp {
	case "a":
		fmt.Printf("=== Starting Experiment A: Handshake Cost Analysis ===\n")
		fmt.Printf("Broker: %s (TCP: %d, QUIC: %d) | Env: %s | Iterations: %d | Interface: %s\n\n",
			*brokerHost, *tcpPort, *quicPort, *envName, *iterations, *iface)

		cfg := benchmark.HandshakeRunConfig{
			BrokerHost:       *brokerHost,
			TCPPort:          *tcpPort,
			QUICPort:         *quicPort,
			Environment:      *envName,
			Iterations:       *iterations,
			Interface:        *iface,
			ResultsDir:       *resultsDir,
			SSLKeyLogPath:    *keylog,
			InsecureTLS:      *insecure,
			ServerName:       *serverName,
			CooldownDuration: *cooldown,
		}

		progressCb := func(r benchmark.HandshakeRunRecord) {
			statusStr := "SUCCESS"
			if !r.Success {
				statusStr = fmt.Sprintf("FAILED (%s)", r.Error)
			}
			fmt.Printf("[Iter %02d] %-7s | App Handshake: %7.2f ms | Baseline RTT: %5.2f ms | %s\n",
				r.Iteration, r.Protocol, r.AppDurationMs, r.BaselineRTTMs, statusStr)
		}

		records, err := benchmark.RunExperimentA(ctx, cfg, progressCb)
		if err != nil && err != context.Canceled {
			log.Fatalf("Experiment A execution failed: %v", err)
		}

		fmt.Printf("\n=== Experiment A Trials Complete: %d records collected ===\n", len(records))
		fmt.Printf("Results CSV saved to: %s/exp_a_handshake_runs.csv\n", *resultsDir)
		fmt.Printf("PCAP files saved to: %s/pcap/\n", *resultsDir)

	default:
		log.Fatalf("Unknown experiment '%s'. Supported options: 'a'", *exp)
	}
}
