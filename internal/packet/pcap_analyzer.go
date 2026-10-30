package packet

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// HandshakeAnalysisResult contains handshake timing metrics extracted from pcap.
type HandshakeAnalysisResult struct {
	PcapPath        string  `json:"pcap_path"`
	Protocol        string  `json:"protocol"`
	TotalDurationMs float64 `json:"total_duration_ms"`
	Round1Ms        float64 `json:"round_1_ms"`
	Round2Ms        float64 `json:"round_2_ms"`
	Round3Ms        float64 `json:"round_3_ms"` // -1.0 indicates Not Applicable (QUIC)
	FirstPktEpoch   float64 `json:"first_pkt_epoch"`
	ConnackEpoch    float64 `json:"connack_epoch"`
	Success         bool    `json:"success"`
	Error           string  `json:"error,omitempty"`
}

type pcapFrameInfo struct {
	frameNum   int
	epoch      float64
	srcIP      string
	dstIP      string
	syn        string
	ack        string
	tlsTypes   string
	mqttType   string
	quicHeader string
	quicType   string
}

// AnalyzeHandshakePCAP parses a capture file to extract handshake and per-RTT timings.
func AnalyzeHandshakePCAP(pcapPath string, proto string, keylogPath string) (*HandshakeAnalysisResult, error) {
	args := []string{
		"-r", pcapPath,
		"-n",
	}

	if keylogPath != "" {
		args = append(args, "-o", fmt.Sprintf("tls.keylog_file:%s", keylogPath))
	}

	args = append(args,
		"-T", "fields",
		"-E", "separator=\t",
		"-e", "frame.number",
		"-e", "frame.time_epoch",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "tcp.flags.syn",
		"-e", "tcp.flags.ack",
		"-e", "tls.handshake.type",
		"-e", "mqtt.msgtype",
		"-e", "quic.header_form",
		"-e", "quic.long.packet_type",
	)

	cmd := exec.Command("tshark", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("tshark pcap analysis failed: %w (stderr: %s)", err, stderr.String())
	}

	lines := strings.Split(stdout.String(), "\n")
	var frames []pcapFrameInfo

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}

		fNum, _ := strconv.Atoi(parts[0])
		epoch, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			continue
		}

		info := pcapFrameInfo{
			frameNum: fNum,
			epoch:    epoch,
		}
		if len(parts) > 2 {
			info.srcIP = parts[2]
		}
		if len(parts) > 3 {
			info.dstIP = parts[3]
		}
		if len(parts) > 4 {
			info.syn = parts[4]
		}
		if len(parts) > 5 {
			info.ack = parts[5]
		}
		if len(parts) > 6 {
			info.tlsTypes = parts[6]
		}
		if len(parts) > 7 {
			info.mqttType = parts[7]
		}
		if len(parts) > 8 {
			info.quicHeader = parts[8]
		}
		if len(parts) > 9 {
			info.quicType = parts[9]
		}

		frames = append(frames, info)
	}

	if len(frames) == 0 {
		return &HandshakeAnalysisResult{
			PcapPath: pcapPath,
			Protocol: proto,
			Success:  false,
			Error:    "no frames found in pcap",
		}, nil
	}

	if proto == "tcp-tls" {
		return analyzeTCPHandshake(pcapPath, frames)
	}
	return analyzeQUICHandshake(pcapPath, frames)
}

func analyzeTCPHandshake(pcapPath string, frames []pcapFrameInfo) (*HandshakeAnalysisResult, error) {
	var tSyn, tSynAck, tClientHello, tServerFinished, tConnect, tConnack float64
	var foundSyn, foundSynAck, foundCH, foundSF, foundConnect, foundConnack bool

	for _, f := range frames {
		// TCP SYN
		if !foundSyn && f.syn == "1" && f.ack == "0" {
			tSyn = f.epoch
			foundSyn = true
			continue
		}
		// TCP SYN-ACK
		if foundSyn && !foundSynAck && f.syn == "1" && f.ack == "1" {
			tSynAck = f.epoch
			foundSynAck = true
			continue
		}
		// TLS ClientHello (type 1)
		if foundSynAck && !foundCH && hasItem(f.tlsTypes, "1") {
			tClientHello = f.epoch
			foundCH = true
			continue
		}
		// TLS Server Finished (type 20) or ServerHello/Certificate/Finished block
		if foundCH && !foundSF && (hasItem(f.tlsTypes, "20") || hasItem(f.tlsTypes, "2")) {
			tServerFinished = f.epoch
			foundSF = true
			continue
		}
		// MQTT CONNECT (type 1)
		if !foundConnect && hasItem(f.mqttType, "1") {
			tConnect = f.epoch
			foundConnect = true
			continue
		}
		// MQTT CONNACK (type 2)
		if foundConnect && !foundConnack && hasItem(f.mqttType, "2") {
			tConnack = f.epoch
			foundConnack = true
			break
		}
	}

	res := &HandshakeAnalysisResult{
		PcapPath: pcapPath,
		Protocol: "tcp-tls",
	}

	if !foundSyn || !foundConnack {
		res.Success = false
		res.Error = "could not identify complete TCP/TLS handshake sequence"
		return res, nil
	}

	res.Success = true
	res.FirstPktEpoch = tSyn
	res.ConnackEpoch = tConnack
	res.TotalDurationMs = (tConnack - tSyn) * 1000.0

	if foundSyn && foundSynAck {
		res.Round1Ms = (tSynAck - tSyn) * 1000.0
	}
	if foundCH && foundSF {
		res.Round2Ms = (tServerFinished - tClientHello) * 1000.0
	}
	if foundConnect && foundConnack {
		res.Round3Ms = (tConnack - tConnect) * 1000.0
	}

	return res, nil
}

func analyzeQUICHandshake(pcapPath string, frames []pcapFrameInfo) (*HandshakeAnalysisResult, error) {
	var tInitial, tServerHandshake, tConnect, tConnack float64
	var foundInitial, foundSH, foundConnect, foundConnack bool

	for _, f := range frames {
		// QUIC Client Initial (type 0)
		if !foundInitial && hasItem(f.quicType, "0") {
			tInitial = f.epoch
			foundInitial = true
			continue
		}
		// QUIC Server Handshake (type 2)
		if foundInitial && !foundSH && hasItem(f.quicType, "2") {
			tServerHandshake = f.epoch
			foundSH = true
			continue
		}
		// MQTT CONNECT (type 1) on QUIC stream, or first short header packet after handshake
		if foundSH && !foundConnect {
			if hasItem(f.mqttType, "1") || f.quicHeader == "0" {
				tConnect = f.epoch
				foundConnect = true
				continue
			}
		}
		// MQTT CONNACK (type 2) on QUIC stream, or server response short header packet
		if foundConnect && !foundConnack {
			if hasItem(f.mqttType, "2") || (f.quicHeader == "0" && f.epoch > tConnect) {
				tConnack = f.epoch
				foundConnack = true
				break
			}
		}
	}

	res := &HandshakeAnalysisResult{
		PcapPath: pcapPath,
		Protocol: "quic",
		Round3Ms: -1.0, // Not applicable for QUIC (no 3rd round)
	}

	if !foundInitial || !foundConnack {
		res.Success = false
		res.Error = "could not identify complete QUIC handshake sequence"
		return res, nil
	}

	res.Success = true
	res.FirstPktEpoch = tInitial
	res.ConnackEpoch = tConnack
	res.TotalDurationMs = (tConnack - tInitial) * 1000.0

	if foundInitial && foundSH {
		res.Round1Ms = (tServerHandshake - tInitial) * 1000.0
	}
	if foundConnect && foundConnack {
		res.Round2Ms = (tConnack - tConnect) * 1000.0
	}

	return res, nil
}

func hasItem(field string, target string) bool {
	if field == "" {
		return false
	}
	items := strings.Split(field, ",")
	for _, item := range items {
		if strings.TrimSpace(item) == target {
			return true
		}
	}
	return false
}
