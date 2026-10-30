package benchmark

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"qtbench/internal/netem"
	"qtbench/internal/packet"
)

// ScenarioID identifies a netem scenario (B0 through B5).
type ScenarioID = string

const (
	ScenarioB0 ScenarioID = "b0-baseline"
	ScenarioB1 ScenarioID = "b1-loss1"
	ScenarioB2 ScenarioID = "b2-loss5"
	ScenarioB3 ScenarioID = "b3-delay50"
	ScenarioB4 ScenarioID = "b4-delay50-loss1"
	ScenarioB5 ScenarioID = "b5-rate1mbps"
)

// AllScenarios lists all Experiment B scenario IDs in order.
var AllScenarios = []ScenarioID{
	ScenarioB0, ScenarioB1, ScenarioB2, ScenarioB3, ScenarioB4, ScenarioB5,
}

// ThroughputRunConfig holds settings for Experiment B.
type ThroughputRunConfig struct {
	BrokerHost       string
	TCPPort          int
	QUICPort         int
	Environment      string
	Iterations       int   // N_B
	MessageCount     int   // 100
	PayloadBytes     int   // 2048
	PublishRateHz    int   // 10 msg/s
	QoS              byte  // 0, 1, or 2
	Topic            string
	Interface        string
	ResultsDir       string
	SSLKeyLogPath    string
	InsecureTLS      bool
	ServerName       string
	Scenarios        []ScenarioID
	NetemInterface   string
	CooldownDuration time.Duration
}

// MessageRunRecord stores the result of a single message-session trial.
type MessageRunRecord struct {
	Iteration         int       `json:"iteration"`
	Scenario          ScenarioID `json:"scenario"`
	Protocol          string    `json:"protocol"`
	QoS               byte      `json:"qos"`
	MessageCount      int       `json:"message_count"`
	SentCount         int       `json:"sent_count"`
	RecvCount         int       `json:"recv_count"`
	FirstSendNs       int64     `json:"first_send_ns"`
	LastAckNs         int64     `json:"last_ack_ns"`
	LatenciesMs       []float64 `json:"latencies_ms,omitempty"`
	TotalPayloadBytes int64     `json:"total_payload_bytes"`
	PcapPath          string    `json:"pcap_path"`
	DeliveriesPath    string    `json:"deliveries_path"`
	Success           bool      `json:"success"`
	Error             string    `json:"error,omitempty"`
	Timestamp         time.Time `json:"timestamp"`
}

// ThroughputProgressCallback is called after each protocol trial completes.
type ThroughputProgressCallback func(scenario ScenarioID, rec MessageRunRecord)

// RunExperimentB executes Experiment B: message-throughput and latency across all netem scenarios.
func RunExperimentB(ctx context.Context, cfg ThroughputRunConfig, progressCb ThroughputProgressCallback) ([]MessageRunRecord, error) {
	if cfg.Iterations < 1 {
		cfg.Iterations = 1
	}
	if cfg.MessageCount < 1 {
		cfg.MessageCount = 100
	}
	if cfg.PayloadBytes < 17 {
		cfg.PayloadBytes = 2048
	}
	if cfg.PublishRateHz < 1 {
		cfg.PublishRateHz = 10
	}
	if cfg.Topic == "" {
		cfg.Topic = "bench/exp-b"
	}
	if cfg.Interface == "" {
		cfg.Interface = "any"
	}
	if cfg.ResultsDir == "" {
		cfg.ResultsDir = "./results"
	}
	if cfg.ServerName == "" {
		cfg.ServerName = "localhost"
	}
	if cfg.CooldownDuration <= 0 {
		cfg.CooldownDuration = 2 * time.Second
	}
	scenarios := cfg.Scenarios
	if len(scenarios) == 0 {
		scenarios = AllScenarios
	}

	pcapDir := filepath.Join(cfg.ResultsDir, "pcap")
	if err := os.MkdirAll(pcapDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create pcap directory: %w", err)
	}

	delivDir := filepath.Join(cfg.ResultsDir, "deliveries")
	if err := os.MkdirAll(delivDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create deliveries directory: %w", err)
	}

	csvPath := filepath.Join(cfg.ResultsDir, "exp_b_runs.csv")
	csvFile, err := os.OpenFile(csvPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open exp_b csv: %w", err)
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()

	fi, _ := csvFile.Stat()
	if fi.Size() == 0 {
		_ = csvWriter.Write([]string{
			"timestamp", "iteration", "scenario", "protocol", "qos",
			"sent", "recv", "first_send_ns", "last_ack_ns",
			"total_payload_bytes", "pcap_path", "deliveries_path", "success", "error",
		})
		csvWriter.Flush()
	}

	protocols := []string{ProtocolTCPTLS, ProtocolQUIC}
	var allRecords []MessageRunRecord

	for iter := 1; iter <= cfg.Iterations; iter++ {
		for _, scen := range scenarios {
			// Apply netem scenario
			if cfg.NetemInterface != "" {
				if err := netem.Apply(scen, cfg.NetemInterface); err != nil {
					return allRecords, fmt.Errorf("netem apply %s failed: %w", scen, err)
				}
				time.Sleep(200 * time.Millisecond)
			}

			for _, proto := range protocols {
				select {
				case <-ctx.Done():
					if cfg.NetemInterface != "" {
						_ = netem.Reset(cfg.NetemInterface)
					}
					return allRecords, ctx.Err()
				default:
				}

				rec, runErr := runOneSession(ctx, cfg, iter, scen, proto, pcapDir, delivDir)
				if runErr != nil {
					rec.Error = runErr.Error()
					rec.Success = false
				}

				allRecords = append(allRecords, rec)
				writeMessageRecord(csvWriter, rec)
				csvWriter.Flush()

				if progressCb != nil {
					progressCb(scen, rec)
				}

				time.Sleep(cfg.CooldownDuration)
			}

			// Reset netem after scenario
			if cfg.NetemInterface != "" {
				_ = netem.Reset(cfg.NetemInterface)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	return allRecords, nil
}

// runOneSession runs a single protocol trial: connect subscriber, connect publisher,
// send N messages at configured rate, collect latencies, stop pcap.
func runOneSession(ctx context.Context, cfg ThroughputRunConfig, iter int, scenario ScenarioID, proto string, pcapDir string, delivDir string) (MessageRunRecord, error) {
	t0 := time.Now()
	brokerAddr := fmt.Sprintf("%s:%d", cfg.BrokerHost, cfg.QUICPort)
	capturePort := cfg.QUICPort
	if proto == ProtocolTCPTLS {
		brokerAddr = fmt.Sprintf("%s:%d", cfg.BrokerHost, cfg.TCPPort)
		capturePort = cfg.TCPPort
	}

	rec := MessageRunRecord{
		Iteration:    iter,
		Scenario:     scenario,
		Protocol:     proto,
		QoS:          cfg.QoS,
		MessageCount: cfg.MessageCount,
		Timestamp:    t0,
	}

	// Capture filter
	tsharkFilter := ""
	if proto == ProtocolTCPTLS {
		tsharkFilter = fmt.Sprintf("tcp port %d and host %s", capturePort, cfg.BrokerHost)
	} else {
		tsharkFilter = fmt.Sprintf("udp port %d and host %s", capturePort, cfg.BrokerHost)
	}

	ts := t0.Format("20060102_150405")
	pcapFileName := fmt.Sprintf("expB_%s_%s_%s_iter%03d_qos%d_%s.pcap",
		cfg.Environment, scenario, proto, iter, cfg.QoS, ts)
	pcapPath := filepath.Join(pcapDir, pcapFileName)
	rec.PcapPath = pcapPath

	delivFileName := fmt.Sprintf("expB_%s_%s_%s_iter%03d_qos%d_%s.csv",
		cfg.Environment, scenario, proto, iter, cfg.QoS, ts)
	delivPath := filepath.Join(delivDir, delivFileName)
	rec.DeliveriesPath = delivPath

	capture, _ := packet.StartCapture(cfg.Interface, tsharkFilter, pcapPath)

	keepalive := uint16(cfg.MessageCount/cfg.PublishRateHz + 30)

	// Connect subscriber (same machine, own client ID)
	subID := fmt.Sprintf("bench-sub-%s-%s-%d-%d", proto, scenario, iter, t0.UnixNano()%100000)
	subOpts := ClientOptions{
		BrokerAddr:    brokerAddr,
		ClientID:      subID,
		CleanSession:  true,
		KeepaliveSec:  keepalive,
		InsecureTLS:   cfg.InsecureTLS,
		ServerName:    cfg.ServerName,
		SSLKeyLogPath: cfg.SSLKeyLogPath,
	}

	var subClient Client
	if proto == ProtocolTCPTLS {
		subClient = NewTCPClient(subOpts)
	} else {
		subClient = NewQUICClient(subOpts)
	}

	subCtx, subCancel := context.WithTimeout(ctx, 30*time.Second)
	defer subCancel()
	if _, err := subClient.Connect(subCtx); err != nil {
		if capture != nil {
			_ = capture.Stop()
		}
		return rec, fmt.Errorf("subscriber connect failed: %w", err)
	}
	defer func() {
		dCtx, dCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = subClient.Disconnect(dCtx)
		dCancel()
	}()

	// Open deliveries CSV for recording individual message latencies
	delivFile, delivErr := os.OpenFile(delivPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	var delivWriter *csv.Writer
	if delivErr == nil {
		delivWriter = csv.NewWriter(delivFile)
		_ = delivWriter.Write([]string{"timestamp", "seq", "qos", "send_ns", "recv_ns", "latency_ms", "payload_len"})
		delivWriter.Flush()
		defer func() {
			if delivWriter != nil {
				delivWriter.Flush()
			}
			if delivFile != nil {
				_ = delivFile.Close()
			}
		}()
	}

	// Collect delivered messages
	var (
		deliveryMu    sync.Mutex
		latenciesMs   []float64
		recvSeqs      = make(map[uint32]struct{})
		totalPayBytes int64
		allClosed     atomic.Bool
	)

	allDelivered := make(chan struct{})

	if err := subClient.Subscribe(ctx, cfg.Topic, cfg.QoS, func(d *DeliveryMetric) {
		deliveryMu.Lock()
		defer deliveryMu.Unlock()
		if _, dup := recvSeqs[d.Seq]; !dup {
			recvSeqs[d.Seq] = struct{}{}
			latenciesMs = append(latenciesMs, d.LatencyMs)
			totalPayBytes += int64(d.PayloadLen)

			if delivWriter != nil {
				_ = delivWriter.Write([]string{
					d.Timestamp.Format(time.RFC3339Nano),
					fmt.Sprintf("%d", d.Seq),
					fmt.Sprintf("%d", d.QoS),
					fmt.Sprintf("%d", d.SendNs),
					fmt.Sprintf("%d", d.RecvNs),
					fmt.Sprintf("%.4f", d.LatencyMs),
					fmt.Sprintf("%d", d.PayloadLen),
				})
			}

			if len(latenciesMs) == cfg.MessageCount {
				if allClosed.CompareAndSwap(false, true) {
					close(allDelivered)
				}
			}
		}
	}); err != nil {
		if capture != nil {
			_ = capture.Stop()
		}
		return rec, fmt.Errorf("subscribe failed: %w", err)
	}

	// Connect publisher
	pubID := fmt.Sprintf("bench-pub-%s-%s-%d-%d", proto, scenario, iter, t0.UnixNano()%100000)
	pubOpts := ClientOptions{
		BrokerAddr:        brokerAddr,
		ClientID:          pubID,
		CleanSession:      true,
		KeepaliveSec:      keepalive,
		InsecureTLS:       cfg.InsecureTLS,
		ServerName:        cfg.ServerName,
		SSLKeyLogPath:     cfg.SSLKeyLogPath,
		EnableMultiStream: true,
	}

	var pubClient Client
	if proto == ProtocolTCPTLS {
		pubClient = NewTCPClient(pubOpts)
	} else {
		pubClient = NewQUICClient(pubOpts)
	}

	pubCtx, pubCancel := context.WithTimeout(ctx, 30*time.Second)
	if _, err := pubClient.Connect(pubCtx); err != nil {
		pubCancel()
		if capture != nil {
			_ = capture.Stop()
		}
		return rec, fmt.Errorf("publisher connect failed: %w", err)
	}
	pubCancel()
	defer func() {
		dCtx, dCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = pubClient.Disconnect(dCtx)
		dCancel()
	}()

	// Publish N messages at configured rate
	interval := time.Second / time.Duration(cfg.PublishRateHz)
	var sentCount int
	var firstSendNs, lastAckNs int64

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for seq := uint32(1); seq <= uint32(cfg.MessageCount); seq++ {
		select {
		case <-ctx.Done():
			goto publishDone
		case <-ticker.C:
		}

		sendNs := time.Now().UnixNano()
		payload := EncodePayload(seq, sendNs, cfg.QoS, cfg.PayloadBytes)

		pubMsgCtx, pubMsgCancel := context.WithTimeout(ctx, 15*time.Second)
		pm, pubErr := pubClient.Publish(pubMsgCtx, cfg.Topic, cfg.QoS, payload)
		pubMsgCancel()

		if pubErr == nil {
			sentCount++
			if firstSendNs == 0 {
				firstSendNs = sendNs
			}
			if pm != nil {
				lastAckNs = pm.AckNs
			} else {
				lastAckNs = time.Now().UnixNano()
			}
		}
	}

publishDone:
	// Wait for all messages to be delivered or timeout
	sessionTimeout := time.Duration(cfg.MessageCount/cfg.PublishRateHz+10) * time.Second
	select {
	case <-allDelivered:
	case <-time.After(sessionTimeout):
	case <-ctx.Done():
	}

	if capture != nil {
		_ = capture.Stop()
	}

	deliveryMu.Lock()
	recvCount := len(recvSeqs)
	finalLatencies := make([]float64, len(latenciesMs))
	copy(finalLatencies, latenciesMs)
	deliveryMu.Unlock()

	rec.SentCount = sentCount
	rec.RecvCount = recvCount
	rec.FirstSendNs = firstSendNs
	rec.LastAckNs = lastAckNs
	rec.LatenciesMs = finalLatencies
	rec.TotalPayloadBytes = totalPayBytes
	rec.Success = sentCount > 0
	return rec, nil
}

func writeMessageRecord(w *csv.Writer, rec MessageRunRecord) {
	_ = w.Write([]string{
		rec.Timestamp.Format("2006-01-02T15:04:05.000000000Z07:00"),
		fmt.Sprintf("%d", rec.Iteration),
		rec.Scenario,
		rec.Protocol,
		fmt.Sprintf("%d", rec.QoS),
		fmt.Sprintf("%d", rec.SentCount),
		fmt.Sprintf("%d", rec.RecvCount),
		fmt.Sprintf("%d", rec.FirstSendNs),
		fmt.Sprintf("%d", rec.LastAckNs),
		fmt.Sprintf("%d", rec.TotalPayloadBytes),
		rec.PcapPath,
		rec.DeliveriesPath,
		fmt.Sprintf("%t", rec.Success),
		rec.Error,
	})
}
