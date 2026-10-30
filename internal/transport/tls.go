package transport

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var (
	keyLogMu   sync.Mutex
	keyLogFile *os.File
)

// InitKeyLogWriter opens or reuses the file for writing NSS TLS key log secrets.
func InitKeyLogWriter(filePath string) (io.Writer, error) {
	keyLogMu.Lock()
	defer keyLogMu.Unlock()

	if filePath == "" {
		filePath = os.Getenv("SSLKEYLOGFILE")
	}
	if filePath == "" {
		return nil, nil
	}

	if keyLogFile != nil {
		return keyLogFile, nil
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for sslkeylogfile: %w", err)
	}

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open sslkeylogfile: %w", err)
	}

	keyLogFile = f
	return keyLogFile, nil
}

// CloseKeyLogWriter closes the active key log file descriptor if open.
func CloseKeyLogWriter() {
	keyLogMu.Lock()
	defer keyLogMu.Unlock()
	if keyLogFile != nil {
		_ = keyLogFile.Close()
		keyLogFile = nil
	}
}

// NewBenchmarkTLSConfig constructs a standardized TLS 1.3 configuration.
// It forces TLS 1.3 as both min and max versions, attaches the SSLKEYLOGFILE writer,
// and sets the ALPN protocol identifier.
func NewBenchmarkTLSConfig(serverName string, insecure bool, keyLogPath string, alpn ...string) (*tls.Config, error) {
	alpns := alpn
	if len(alpns) == 0 {
		alpns = []string{"mqtt"}
	}

	writer, err := InitKeyLogWriter(keyLogPath)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
		NextProtos:         alpns,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		KeyLogWriter:       writer,
	}

	return cfg, nil
}
