package benchmark

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"qtbench/internal/netem"
	"qtbench/internal/packet"
)

// HandshakeRunConfig holds execution settings for Experiment A.
type HandshakeRunConfig struct {
	BrokerHost       string
	TCPPort          int
	QUICPort         int
	Environment      string // "wired" or "wireless"
	Iterations       int    // N_A
	Interface        string // Network interface for packet capture
	ResultsDir       string
	SSLKeyLogPath    string
	InsecureTLS      bool
	ServerName       string
	CooldownDuration time.Duration
	CaptureFilter    string // Optional custom tshark capture filter
}

// HandshakeRunRecord stores the execution result of a single 1-RTT handshake trial.
type HandshakeRunRecord struct {
	Iteration     int       `json:"iteration"`
	Protocol      string    `json:"protocol"`
	BrokerAddr    string    `json:"broker_addr"`
	BaselineRTTMs float64   `json:"baseline_rtt_ms"`
	AppDurationMs float64   `json:"app_duration_ms"`
	PcapPath      string    `json:"pcap_path"`
	Success       bool      `json:"success"`
	Error         string    `json:"error,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// HandshakeProgressCallback is invoked after each trial completes.
type HandshakeProgressCallback func(record HandshakeRunRecord)

// RunExperimentA executes Experiment A: interleaved 1-RTT connection handshakes.
func RunExperimentA(ctx context.Context, cfg HandshakeRunConfig, progressCb HandshakeProgressCallback) ([]HandshakeRunRecord, error) {
	if cfg.Iterations < 1 {
		cfg.Iterations = 1
	}
	if cfg.CooldownDuration <= 0 {
		cfg.CooldownDuration = 1 * time.Second
	}
	if cfg.ResultsDir == "" {
		cfg.ResultsDir = "./results"
	}
	if cfg.Interface == "" {
		cfg.Interface = "any"
	}
	if cfg.ServerName == "" {
		cfg.ServerName = "localhost"
	}

	pcapDir := filepath.Join(cfg.ResultsDir, "pcap")
	if err := os.MkdirAll(pcapDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create pcap directory: %w", err)
	}

	csvPath := filepath.Join(cfg.ResultsDir, "exp_a_handshake_runs.csv")
	csvFile, err := os.OpenFile(csvPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open csv file: %w", err)
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()

	// Write CSV header if file is empty
	fi, _ := csvFile.Stat()
	if fi.Size() == 0 {
		_ = csvWriter.Write([]string{
			"timestamp", "iteration", "protocol", "broker_addr",
			"baseline_rtt_ms", "app_duration_ms", "pcap_path", "success", "error",
		})
		csvWriter.Flush()
	}

	protocols := []string{ProtocolTCPTLS, ProtocolQUIC}
	var records []HandshakeRunRecord

	for iter := 1; iter <= cfg.Iterations; iter++ {
		for _, proto := range protocols {
			select {
			case <-ctx.Done():
				return records, ctx.Err()
			default:
			}

			brokerAddr := fmt.Sprintf("%s:%d", cfg.BrokerHost, cfg.QUICPort)
			capturePort := cfg.QUICPort
			if proto == ProtocolTCPTLS {
				brokerAddr = fmt.Sprintf("%s:%d", cfg.BrokerHost, cfg.TCPPort)
				capturePort = cfg.TCPPort
			}

			// 1. Measure baseline RTT with ping immediately before trial
			baselineRTT := 0.0
			pingProf, err := netem.ProbeEnvironment(ctx, cfg.BrokerHost, cfg.Environment, "")
			if err == nil && pingProf != nil {
				baselineRTT = pingProf.RTTAvgMs
			}

			// 2. Prepare pcap path and capture filter
			timestampStr := time.Now().Format("20060102_150405")
			pcapFileName := fmt.Sprintf("expA_%s_%s_iter%03d_%s.pcap", cfg.Environment, proto, iter, timestampStr)
			pcapPath := filepath.Join(pcapDir, pcapFileName)

			tsharkFilter := cfg.CaptureFilter
			if tsharkFilter == "" {
				if proto == ProtocolTCPTLS {
					tsharkFilter = fmt.Sprintf("tcp port %d and host %s", capturePort, cfg.BrokerHost)
				} else {
					tsharkFilter = fmt.Sprintf("udp port %d and host %s", capturePort, cfg.BrokerHost)
				}
			}

			// 3. Start background tshark capture
			capture, capErr := packet.StartCapture(cfg.Interface, tsharkFilter, pcapPath)

			// 4. Construct fresh client for 1-RTT connection (no session resumption)
			cid := fmt.Sprintf("expA-%s-%d-%d", proto, iter, time.Now().UnixNano()%100000)
			opts := ClientOptions{
				BrokerAddr:        brokerAddr,
				ClientID:          cid,
				CleanSession:      true,
				KeepaliveSec:      60,
				InsecureTLS:       cfg.InsecureTLS,
				ServerName:        cfg.ServerName,
				SSLKeyLogPath:     cfg.SSLKeyLogPath,
				EnableMultiStream: true,
			}

			var client Client
			if proto == ProtocolTCPTLS {
				client = NewTCPClient(opts)
			} else {
				client = NewQUICClient(opts)
			}

			// 5. Execute 1-RTT connection attempt
			connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			t0 := time.Now()
			hs, connectErr := client.Connect(connectCtx)
			cancel()

			// 6. Gracefully disconnect client
			if connectErr == nil {
				discCtx, dCancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = client.Disconnect(discCtx)
				dCancel()
			}

			// 7. Stop tshark capture
			if capErr == nil && capture != nil {
				_ = capture.Stop()
			}

			record := HandshakeRunRecord{
				Iteration:     iter,
				Protocol:      proto,
				BrokerAddr:    brokerAddr,
				BaselineRTTMs: baselineRTT,
				PcapPath:      pcapPath,
				Timestamp:     t0,
			}

			if connectErr != nil {
				record.Success = false
				record.Error = connectErr.Error()
			} else {
				record.Success = true
				record.AppDurationMs = hs.DurationMs
			}

			records = append(records, record)

			// 8. Write record to CSV
			_ = csvWriter.Write([]string{
				record.Timestamp.Format(time.RFC3339Nano),
				fmt.Sprintf("%d", record.Iteration),
				record.Protocol,
				record.BrokerAddr,
				fmt.Sprintf("%.3f", record.BaselineRTTMs),
				fmt.Sprintf("%.3f", record.AppDurationMs),
				record.PcapPath,
				fmt.Sprintf("%t", record.Success),
				record.Error,
			})
			csvWriter.Flush()

			if progressCb != nil {
				progressCb(record)
			}

			// Cooldown between trials
			time.Sleep(cfg.CooldownDuration)
		}
	}

	return records, nil
}
