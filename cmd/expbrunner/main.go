// Command expbrunner: runner for Experiment B (message throughput and latency).
// Executes all 6 netem scenarios (B0-B5) for both TCP/TLS and QUIC,
// collecting per-message latencies and pcap for overhead calculation.
//
// Usage:
//
//	expbrunner -broker-ip <IP> -tcp-port 8883 -quic-port 8884 \
//	           -env wired -iface eth0 -netem-iface eth0 \
//	           -qos 1 -count 100 -rate 10 -iterations 5 \
//	           -keylog results/exp_b/sslkeys.log \
//	           -out results/exp_b
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"qtbench/internal/benchmark"
)

func main() {
	brokerIP := flag.String("broker-ip", "127.0.0.1", "Broker IP address")
	tcpPort := flag.Int("tcp-port", 8883, "TCP/TLS broker port")
	quicPort := flag.Int("quic-port", 8884, "QUIC broker port")
	env := flag.String("env", "wired", "Environment label (wired or wireless)")
	iface := flag.String("iface", "any", "Network interface for tshark packet capture")
	netIface := flag.String("netem-iface", "", "Network interface for tc netem (empty = skip netem)")
	qos := flag.Int("qos", 0, "MQTT QoS level (0, 1, or 2) (default 0)")
	count := flag.Int("count", 100, "Number of messages per session")
	rate := flag.Int("rate", 10, "Publish rate in messages/second")
	iterations := flag.Int("iterations", 5, "Number of iterations per scenario")
	keylog := flag.String("keylog", "", "Path to SSLKEYLOGFILE for TLS decryption")
	outDir := flag.String("out", "results/exp_b", "Output directory for CSV and pcap files")
	serverName := flag.String("server-name", "localhost", "TLS server name")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	topic := flag.String("topic", "bench/exp-b", "MQTT topic to use")
	cooldown := flag.Duration("cooldown", 2*time.Second, "Cooldown duration between trials")

	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("Failed to create output dir: %v", err)
	}

	if *keylog != "" {
		if err := os.MkdirAll(filepath.Dir(*keylog), 0755); err != nil {
			log.Printf("Warning: could not create keylog dir: %v", err)
		}
	}

	cfg := benchmark.ThroughputRunConfig{
		BrokerHost:       *brokerIP,
		TCPPort:          *tcpPort,
		QUICPort:         *quicPort,
		Environment:      *env,
		Iterations:       *iterations,
		MessageCount:     *count,
		PayloadBytes:     2048,
		PublishRateHz:    *rate,
		QoS:              byte(*qos),
		Topic:            *topic,
		Interface:        *iface,
		NetemInterface:   *netIface,
		ResultsDir:       *outDir,
		SSLKeyLogPath:    *keylog,
		InsecureTLS:      *insecure,
		ServerName:       *serverName,
		CooldownDuration: *cooldown,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("Starting Experiment B | Env:%s Broker:%s TCP:%d QUIC:%d QoS:%d Count:%d Rate:%d/s Iters:%d",
		*env, *brokerIP, *tcpPort, *quicPort, *qos, *count, *rate, *iterations)

	records, err := benchmark.RunExperimentB(ctx, cfg, func(scenario string, rec benchmark.MessageRunRecord) {
		log.Printf("[%s/%s] iter=%d sent=%d recv=%d latency_samples=%d success=%v",
			scenario, rec.Protocol, rec.Iteration,
			rec.SentCount, rec.RecvCount, len(rec.LatenciesMs), rec.Success)
		if rec.Error != "" {
			log.Printf("  error: %s", rec.Error)
		}
	})
	if err != nil {
		log.Printf("RunExperimentB returned error: %v", err)
	}

	log.Printf("Total trials completed: %d", len(records))
	log.Printf("Results written to: %s", *outDir)
	log.Println("Done. Run analyzexpb to generate report tables.")
}
