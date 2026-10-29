package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"qtbench/internal/benchmark"
)

func main() {
	proto := flag.String("proto", "quic", "Transport protocol: 'quic' or 'tcp-tls'")
	broker := flag.String("broker", "127.0.0.1:14567", "Broker address (host:port)")
	topic := flag.String("topic", "benchmark/test", "MQTT topic")
	qos := flag.Int("qos", 1, "MQTT QoS level (0, 1, 2)")
	expected := flag.Int("expected", 100, "Expected number of messages to receive")
	waitTimeout := flag.Duration("timeout", 30*time.Second, "Maximum wait time after last received message")
	clientID := flag.String("client-id", "", "MQTT Client ID")
	keylog := flag.String("keylog", "", "Path to SSLKEYLOGFILE for TLS secrets")
	resultsDir := flag.String("results", "./results", "Directory to write CSV metrics")
	runID := flag.String("run-id", "", "Unique run identifier")
	keepalive := flag.Int("keepalive", 60, "MQTT Keepalive in seconds")
	cleanSession := flag.Bool("clean", true, "MQTT Clean Session flag")
	insecure := flag.Bool("insecure", true, "Skip TLS verification")
	serverName := flag.String("servername", "localhost", "TLS SNI server name")
	flag.Parse()

	if *runID == "" {
		*runID = fmt.Sprintf("sub-%s-%d", *proto, time.Now().UnixNano()%1000000)
	}

	opts := benchmark.ClientOptions{
		BrokerAddr:    *broker,
		ClientID:      *clientID,
		CleanSession:  *cleanSession,
		KeepaliveSec:  uint16(*keepalive),
		InsecureTLS:   *insecure,
		ServerName:    *serverName,
		SSLKeyLogPath: *keylog,
	}

	var client benchmark.Client
	switch *proto {
	case benchmark.ProtocolTCPTLS:
		client = benchmark.NewTCPClient(opts)
	case benchmark.ProtocolQUIC:
		client = benchmark.NewQUICClient(opts)
	default:
		log.Fatalf("Unknown protocol %s. Use 'quic' or 'tcp-tls'", *proto)
	}

	rec, err := benchmark.NewMetricsRecorder(*resultsDir, *runID)
	if err != nil {
		log.Fatalf("Failed to initialize metrics recorder: %v", err)
	}
	defer rec.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	hs, err := client.Connect(ctx)
	cancel()
	if err != nil {
		rec.RecordHandshake(&benchmark.HandshakeResult{
			Protocol:   *proto,
			BrokerAddr: *broker,
			Success:    false,
			Error:      err.Error(),
			Timestamp:  time.Now(),
		})
		log.Fatalf("Connection failed: %v", err)
	}
	rec.RecordHandshake(hs)
	fmt.Printf("[%s] Connected to %s in %.2f ms\n", *proto, *broker, hs.DurationMs)

	defer func() {
		discCtx, dCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = client.Disconnect(discCtx)
		dCancel()
	}()

	var mu sync.Mutex
	var latencies []float64
	var totalBytes int64
	receivedSeqs := make(map[uint32]bool)
	var firstMsgTime, lastMsgTime time.Time
	doneCh := make(chan struct{})

	subHandler := func(m *benchmark.DeliveryMetric) {
		mu.Lock()
		defer mu.Unlock()

		if !receivedSeqs[m.Seq] {
			receivedSeqs[m.Seq] = true
			latencies = append(latencies, m.LatencyMs)
			totalBytes += int64(m.PayloadLen)

			now := time.Now()
			if firstMsgTime.IsZero() {
				firstMsgTime = now
			}
			lastMsgTime = now

			rec.RecordDelivery(m)

			if len(receivedSeqs) >= *expected {
				select {
				case <-doneCh:
				default:
					close(doneCh)
				}
			}
		}
	}

	subCtx, sCancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Subscribe(subCtx, *topic, byte(*qos), subHandler)
	sCancel()
	if err != nil {
		log.Fatalf("Failed to subscribe: %v", err)
	}
	fmt.Printf("[%s] Subscribed to '%s' (QoS %d), awaiting %d messages...\n", *proto, *topic, *qos, *expected)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case <-doneCh:
		fmt.Printf("[%s] Received all %d expected messages.\n", *proto, *expected)
	case <-time.After(*waitTimeout):
		fmt.Printf("[%s] Wait timeout reached (%v).\n", *proto, *waitTimeout)
	case <-sigCh:
		fmt.Printf("\n[%s] Interrupted by user signal.\n", *proto)
	}

	mu.Lock()
	transferSec := 0.0
	if !firstMsgTime.IsZero() && !lastMsgTime.IsZero() && lastMsgTime.After(firstMsgTime) {
		transferSec = lastMsgTime.Sub(firstMsgTime).Seconds()
	}
	stats := benchmark.ComputeStats(latencies, totalBytes, transferSec, *expected)
	mu.Unlock()

	fmt.Printf("\n=== [%s] Benchmark Summary ===\n", *proto)
	fmt.Printf("Received: %d / %d (%.2f%%)\n", stats.Count, *expected, stats.DeliveryPct)
	fmt.Printf("Latency (ms) - Mean: %.2f, StdDev: %.2f, Min: %.2f, Median: %.2f, P95: %.2f, P99: %.2f, Max: %.2f\n",
		stats.Mean, stats.StdDev, stats.Min, stats.Median, stats.P95, stats.P99, stats.Max)
	fmt.Printf("Throughput: %.4f Mbps (Transfer duration: %.3f s, Bytes: %d)\n",
		stats.Throughput, transferSec, totalBytes)
}
