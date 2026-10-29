package benchmark

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	ProtocolTCPTLS = "tcp-tls"
	ProtocolQUIC   = "quic"

	MagicBytes = 0x51544231 // "QTB1" in hex
)

var (
	ErrPayloadTooShort = errors.New("received payload is shorter than header size")
	ErrInvalidMagic    = errors.New("payload does not contain valid magic bytes")
)

// Config represents the benchmark configuration file format.
type Config struct {
	Broker struct {
		Host               string `json:"host"`
		TCPTLSPort         int    `json:"tcp_tls_port"`
		QUICPort           int    `json:"quic_port"`
		InsecureSkipVerify bool   `json:"insecure_skip_verify"`
		ServerName         string `json:"server_name"`
	} `json:"broker"`
	FixedParameters struct {
		TLSVersion           string `json:"tls_version"`
		QoS                  int    `json:"qos"`
		KeepaliveSec         int    `json:"keepalive_sec"`
		CleanSession         bool   `json:"clean_session"`
		PublishRateMsgPerSec int    `json:"publish_rate_msg_per_sec"`
		MessageCount         int    `json:"message_count"`
		PayloadSizeBytes     int    `json:"payload_size_bytes"`
		QUICMultistream      bool   `json:"quic_multistream"`
		MTUBytes             int    `json:"mtu_bytes"`
		Topic                string `json:"topic"`
	} `json:"fixed_parameters"`
	Logging struct {
		ResultsDir    string `json:"results_dir"`
		SSLKeyLogFile string `json:"sslkeylog_file"`
	} `json:"logging"`
}

// LoadConfig loads benchmark configuration from a JSON file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	return &cfg, nil
}

// MessageHeader contains metadata embedded in each benchmark message.
type MessageHeader struct {
	Seq      uint32
	SendNs   int64
	QoS      byte
	TotalLen int
}

// EncodePayload builds a benchmark message payload with embedded metadata and padding.
func EncodePayload(seq uint32, sendNs int64, qos byte, totalSize int) []byte {
	if totalSize < 17 {
		totalSize = 17
	}

	buf := make([]byte, totalSize)
	// Header format:
	// [0..3]: Magic (4 bytes)
	// [4..7]: Seq (4 bytes)
	// [8..15]: SendTimestampNs (8 bytes)
	// [16]: QoS (1 byte)
	// [17..]: Padding bytes
	binary.BigEndian.PutUint32(buf[0:4], MagicBytes)
	binary.BigEndian.PutUint32(buf[4:8], seq)
	binary.BigEndian.PutUint64(buf[8:16], uint64(sendNs))
	buf[16] = qos

	for i := 17; i < totalSize; i++ {
		buf[i] = byte(i % 256)
	}

	return buf
}

// DecodePayload parses metadata from a received benchmark payload.
func DecodePayload(data []byte) (*MessageHeader, error) {
	if len(data) < 17 {
		return nil, ErrPayloadTooShort
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != MagicBytes {
		return nil, ErrInvalidMagic
	}

	seq := binary.BigEndian.Uint32(data[4:8])
	sendNs := int64(binary.BigEndian.Uint64(data[8:16]))
	qos := data[16]

	return &MessageHeader{
		Seq:      seq,
		SendNs:   sendNs,
		QoS:      qos,
		TotalLen: len(data),
	}, nil
}

// HandshakeResult stores connection establishment metrics.
type HandshakeResult struct {
	Protocol   string        `json:"protocol"`
	BrokerAddr string        `json:"broker_addr"`
	DurationMs float64       `json:"duration_ms"`
	Duration   time.Duration `json:"duration_ns"`
	Success    bool          `json:"success"`
	Error      string        `json:"error,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
}

// PublishMetric records metrics for a single published message.
type PublishMetric struct {
	Seq        uint32    `json:"seq"`
	QoS        byte      `json:"qos"`
	SendNs     int64     `json:"send_ns"`
	AckNs      int64     `json:"ack_ns"`
	DurationMs float64   `json:"duration_ms"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// DeliveryMetric records metrics for a single received message at the subscriber.
type DeliveryMetric struct {
	Seq        uint32    `json:"seq"`
	QoS        byte      `json:"qos"`
	SendNs     int64     `json:"send_ns"`
	RecvNs     int64     `json:"recv_ns"`
	LatencyMs  float64   `json:"latency_ms"`
	PayloadLen int       `json:"payload_len"`
	Timestamp  time.Time `json:"timestamp"`
}
