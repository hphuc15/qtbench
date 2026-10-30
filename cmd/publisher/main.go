package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"qtbench/internal/benchmark"
)

func main() {
	proto := flag.String("proto", "quic", "Transport protocol: 'quic' or 'tcp-tls'")
	broker := flag.String("broker", "127.0.0.1:14567", "Broker address (host:port)")
	topic := flag.String("topic", "benchmark/test", "MQTT topic")
	qos := flag.Int("qos", 0, "MQTT QoS level (0, 1, 2) (default 0)")
	count := flag.Int("count", 100, "Number of messages to publish")
	rate := flag.Int("rate", 10, "Publish rate in messages per second")
	size := flag.Int("size", 2048, "Payload size in bytes")
	clientID := flag.String("client-id", "", "MQTT Client ID")
	keylog := flag.String("keylog", "", "Path to SSLKEYLOGFILE for TLS secrets")
	resultsDir := flag.String("results", "./results", "Directory to write CSV metrics")
	runID := flag.String("run-id", "", "Unique run identifier")
	multistream := flag.Bool("multistream", true, "Enable QUIC multistream publishing")
	keepalive := flag.Int("keepalive", 60, "MQTT Keepalive in seconds")
	cleanSession := flag.Bool("clean", true, "MQTT Clean Session flag")
	insecure := flag.Bool("insecure", true, "Skip TLS verification")
	serverName := flag.String("servername", "localhost", "TLS SNI server name")
	flag.Parse()

	if *runID == "" {
		*runID = fmt.Sprintf("pub-%s-%d", *proto, time.Now().UnixNano()%1000000)
	}

	opts := benchmark.ClientOptions{
		BrokerAddr:        *broker,
		ClientID:          *clientID,
		CleanSession:      *cleanSession,
		KeepaliveSec:      uint16(*keepalive),
		InsecureTLS:       *insecure,
		ServerName:        *serverName,
		SSLKeyLogPath:     *keylog,
		EnableMultiStream: *multistream,
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

	interval := time.Second
	if *rate > 0 {
		interval = time.Duration(1e9 / *rate)
	}

	fmt.Printf("[%s] Publishing %d messages (%d bytes each) to '%s' at %d msg/s (QoS %d)...\n",
		*proto, *count, *size, *topic, *rate, *qos)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	successCount := 0
	for i := 1; i <= *count; i++ {
		sendNs := time.Now().UnixNano()
		payload := benchmark.EncodePayload(uint32(i), sendNs, byte(*qos), *size)

		pubCtx, pCancel := context.WithTimeout(context.Background(), 5*time.Second)
		metric, err := client.Publish(pubCtx, *topic, byte(*qos), payload)
		pCancel()

		if err != nil {
			rec.RecordPublish(&benchmark.PublishMetric{
				Seq:       uint32(i),
				QoS:       byte(*qos),
				SendNs:    sendNs,
				Success:   false,
				Error:     err.Error(),
				Timestamp: time.Now(),
			})
			fmt.Printf("Message #%d failed: %v\n", i, err)
		} else {
			metric.Seq = uint32(i)
			rec.RecordPublish(metric)
			successCount++
		}

		if i < *count {
			<-ticker.C
		}
	}

	fmt.Printf("[%s] Publisher finished: %d/%d messages sent successfully.\n", *proto, successCount, *count)
	os.Exit(0)
}
