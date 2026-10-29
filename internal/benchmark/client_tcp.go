package benchmark

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hphuc15/mqttOQ/packet"
	"qtbench/internal/transport"
)

var (
	ErrTCPAlreadyConnected = errors.New("tcp client is already connected")
	ErrTCPNotConnected     = errors.New("tcp client is not connected")
	ErrConnackRejected     = errors.New("mqtt broker rejected connection in connack")
)

// TCPClient implements Client over standard TCP with TLS 1.3.
type TCPClient struct {
	opts ClientOptions

	conn    *tls.Conn
	writeMu sync.Mutex

	handler DeliveryHandler

	ackMu      sync.Mutex
	ackWaiters map[uint16]chan packet.ControlPacket
	packetID   uint32

	stopCh    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	connected atomic.Bool
}

// NewTCPClient creates a new benchmark client for MQTT over TCP/TLS 1.3.
func NewTCPClient(opts ClientOptions) *TCPClient {
	if opts.ClientID == "" {
		opts.ClientID = fmt.Sprintf("bench-tcp-%d", time.Now().UnixNano()%1000000)
	}
	if opts.KeepaliveSec == 0 {
		opts.KeepaliveSec = 60
	}

	return &TCPClient{
		opts:       opts,
		ackWaiters: make(map[uint16]chan packet.ControlPacket),
		stopCh:     make(chan struct{}),
	}
}

func (c *TCPClient) nextPacketID() uint16 {
	id := atomic.AddUint32(&c.packetID, 1)
	val := uint16(id % 65535)
	if val == 0 {
		return 1
	}
	return val
}

// Connect dials TCP with TLS 1.3 and performs the MQTT CONNECT/CONNACK exchange.
func (c *TCPClient) Connect(ctx context.Context) (*HandshakeResult, error) {
	if c.connected.Load() {
		return nil, ErrTCPAlreadyConnected
	}

	tlsCfg, err := transport.NewBenchmarkTLSConfig(c.opts.ServerName, c.opts.InsecureTLS, c.opts.SSLKeyLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS 1.3: %w", err)
	}

	t0 := time.Now()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := tls.DialWithDialer(dialer, "tcp", c.opts.BrokerAddr, tlsCfg)
	if err != nil {
		return &HandshakeResult{
			Protocol:   ProtocolTCPTLS,
			BrokerAddr: c.opts.BrokerAddr,
			Success:    false,
			Error:      err.Error(),
			Timestamp:  t0,
		}, fmt.Errorf("tcp/tls dial failed: %w", err)
	}
	c.conn = rawConn

	connectPkt := &packet.ConnectPacket{
		ProtocolName:     "MQTT",
		ProtocolLevel:    4,
		CleanSession:     c.opts.CleanSession,
		KeepAlive:        c.opts.KeepaliveSec,
		ClientIdentifier: c.opts.ClientID,
	}

	if err := connectPkt.Encode(c.conn); err != nil {
		_ = c.conn.Close()
		return &HandshakeResult{
			Protocol:   ProtocolTCPTLS,
			BrokerAddr: c.opts.BrokerAddr,
			Success:    false,
			Error:      err.Error(),
			Timestamp:  t0,
		}, fmt.Errorf("failed to send CONNECT: %w", err)
	}

	resp, err := packet.ReadPacket(c.conn)
	if err != nil {
		_ = c.conn.Close()
		return &HandshakeResult{
			Protocol:   ProtocolTCPTLS,
			BrokerAddr: c.opts.BrokerAddr,
			Success:    false,
			Error:      err.Error(),
			Timestamp:  t0,
		}, fmt.Errorf("failed to read CONNACK: %w", err)
	}

	connack, ok := resp.(*packet.ConnackPacket)
	if !ok {
		_ = c.conn.Close()
		return &HandshakeResult{
			Protocol:   ProtocolTCPTLS,
			BrokerAddr: c.opts.BrokerAddr,
			Success:    false,
			Error:      "unexpected packet type awaiting CONNACK",
			Timestamp:  t0,
		}, fmt.Errorf("expected CONNACK, got %T", resp)
	}

	if connack.ReturnCode != 0 {
		_ = c.conn.Close()
		return &HandshakeResult{
			Protocol:   ProtocolTCPTLS,
			BrokerAddr: c.opts.BrokerAddr,
			Success:    false,
			Error:      fmt.Sprintf("connack return code: %d", connack.ReturnCode),
			Timestamp:  t0,
		}, fmt.Errorf("%w: code %d", ErrConnackRejected, connack.ReturnCode)
	}

	handshakeDuration := time.Since(t0)
	c.connected.Store(true)

	c.wg.Add(1)
	go c.readLoop()
	go c.keepaliveLoop()

	return &HandshakeResult{
		Protocol:   ProtocolTCPTLS,
		BrokerAddr: c.opts.BrokerAddr,
		Duration:   handshakeDuration,
		DurationMs: float64(handshakeDuration.Microseconds()) / 1000.0,
		Success:    true,
		Timestamp:  t0,
	}, nil
}

func (c *TCPClient) readLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		pkt, err := packet.ReadPacket(c.conn)
		if err != nil {
			return
		}

		switch p := pkt.(type) {
		case *packet.PublishPacket:
			c.handleIncomingPublish(p)
		case *packet.PubackPacket:
			c.notifyAckWaiter(p.PacketIdentifier, p)
		case *packet.PubrecPacket:
			c.notifyAckWaiter(p.PacketIdentifier, p)
		case *packet.PubcompPacket:
			c.notifyAckWaiter(p.PacketIdentifier, p)
		case *packet.SubackPacket:
			c.notifyAckWaiter(p.PacketIdentifier, p)
		case *packet.PingrespPacket:
			// Ping response received
		}
	}
}

func (c *TCPClient) handleIncomingPublish(p *packet.PublishPacket) {
	recvNs := time.Now().UnixNano()
	qos := byte(p.Config.QosLevel)

	if qos == 1 {
		ack := &packet.PubackPacket{PacketIdentifier: p.PacketIdentifier}
		_ = c.writePacket(ack)
	} else if qos == 2 {
		rec := &packet.PubrecPacket{PacketIdentifier: p.PacketIdentifier}
		_ = c.writePacket(rec)
	}

	if c.handler != nil {
		hdr, err := DecodePayload(p.Payload)
		if err == nil {
			latencyMs := float64(recvNs-hdr.SendNs) / 1e6
			c.handler(&DeliveryMetric{
				Seq:        hdr.Seq,
				QoS:        qos,
				SendNs:     hdr.SendNs,
				RecvNs:     recvNs,
				LatencyMs:  latencyMs,
				PayloadLen: len(p.Payload),
				Timestamp:  time.Now(),
			})
		}
	}
}

func (c *TCPClient) notifyAckWaiter(packetID uint16, pkt packet.ControlPacket) {
	c.ackMu.Lock()
	ch, ok := c.ackWaiters[packetID]
	c.ackMu.Unlock()

	if ok && ch != nil {
		select {
		case ch <- pkt:
		default:
		}
	}
}

func (c *TCPClient) writePacket(pkt packet.ControlPacket) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.conn == nil {
		return ErrTCPNotConnected
	}
	return pkt.Encode(c.conn)
}

// Publish sends a PUBLISH packet and waits for acknowledgment when QoS > 0.
func (c *TCPClient) Publish(ctx context.Context, topic string, qos byte, payload []byte) (*PublishMetric, error) {
	if !c.connected.Load() {
		return nil, ErrTCPNotConnected
	}

	var pid uint16
	var ackCh chan packet.ControlPacket

	if qos > 0 {
		pid = c.nextPacketID()
		ackCh = make(chan packet.ControlPacket, 1)
		c.ackMu.Lock()
		c.ackWaiters[pid] = ackCh
		c.ackMu.Unlock()
		defer func() {
			c.ackMu.Lock()
			delete(c.ackWaiters, pid)
			c.ackMu.Unlock()
		}()
	}

	pub := &packet.PublishPacket{
		Config: packet.PublishOthersConfig{
			QosLevel: packet.QualityOfService(qos),
		},
		TopicName:        topic,
		PacketIdentifier: pid,
		Payload:          payload,
	}

	sendNs := time.Now().UnixNano()
	t0 := time.Now()

	if err := c.writePacket(pub); err != nil {
		return &PublishMetric{
			QoS:       qos,
			SendNs:    sendNs,
			Success:   false,
			Error:     err.Error(),
			Timestamp: t0,
		}, err
	}

	if qos == 0 {
		return &PublishMetric{
			QoS:        0,
			SendNs:     sendNs,
			AckNs:      sendNs,
			DurationMs: 0.0,
			Success:    true,
			Timestamp:  t0,
		}, nil
	}

	if qos == 1 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.stopCh:
			return nil, ErrTCPNotConnected
		case resp := <-ackCh:
			ackNs := time.Now().UnixNano()
			durMs := float64(ackNs-sendNs) / 1e6
			if _, ok := resp.(*packet.PubackPacket); ok {
				return &PublishMetric{
					QoS:        1,
					SendNs:     sendNs,
					AckNs:      ackNs,
					DurationMs: durMs,
					Success:    true,
					Timestamp:  t0,
				}, nil
			}
			return nil, fmt.Errorf("unexpected ack packet: %T", resp)
		}
	}

	// QoS 2 flow: PUBLISH -> PUBREC -> PUBREL -> PUBCOMP
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.stopCh:
		return nil, ErrTCPNotConnected
	case resp := <-ackCh:
		if _, ok := resp.(*packet.PubrecPacket); !ok {
			return nil, fmt.Errorf("expected PUBREC, got %T", resp)
		}
	}

	rel := &packet.PubrelPacket{PacketIdentifier: pid}
	if err := c.writePacket(rel); err != nil {
		return nil, fmt.Errorf("failed to send PUBREL: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.stopCh:
		return nil, ErrTCPNotConnected
	case resp := <-ackCh:
		ackNs := time.Now().UnixNano()
		durMs := float64(ackNs-sendNs) / 1e6
		if _, ok := resp.(*packet.PubcompPacket); ok {
			return &PublishMetric{
				QoS:        2,
				SendNs:     sendNs,
				AckNs:      ackNs,
				DurationMs: durMs,
				Success:    true,
				Timestamp:  t0,
			}, nil
		}
		return nil, fmt.Errorf("expected PUBCOMP, got %T", resp)
	}
}

// Subscribe subscribes to a topic filter with given QoS.
func (c *TCPClient) Subscribe(ctx context.Context, topic string, qos byte, handler DeliveryHandler) error {
	if !c.connected.Load() {
		return ErrTCPNotConnected
	}

	c.handler = handler
	pid := c.nextPacketID()
	ackCh := make(chan packet.ControlPacket, 1)

	c.ackMu.Lock()
	c.ackWaiters[pid] = ackCh
	c.ackMu.Unlock()
	defer func() {
		c.ackMu.Lock()
		delete(c.ackWaiters, pid)
		c.ackMu.Unlock()
	}()

	sub := &packet.SubscribePacket{
		PacketIdentifier: pid,
		Subscriptions: []packet.TopicSubscription{
			{TopicFilter: topic, RequestedQos: packet.QualityOfService(qos)},
		},
	}

	if err := c.writePacket(sub); err != nil {
		return fmt.Errorf("failed to send SUBSCRIBE: %w", err)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.stopCh:
		return ErrTCPNotConnected
	case resp := <-ackCh:
		if _, ok := resp.(*packet.SubackPacket); ok {
			return nil
		}
		return fmt.Errorf("unexpected subscribe ack: %T", resp)
	}
}

func (c *TCPClient) keepaliveLoop() {
	if c.opts.KeepaliveSec == 0 {
		return
	}
	interval := time.Duration(c.opts.KeepaliveSec) * time.Second / 2
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			if !c.connected.Load() {
				return
			}
			ping := &packet.PingreqPacket{}
			_ = c.writePacket(ping)
		}
	}
}

// Disconnect sends DISCONNECT and closes the network socket.
func (c *TCPClient) Disconnect(ctx context.Context) error {
	if !c.connected.Load() {
		return nil
	}

	c.closeOnce.Do(func() {
		close(c.stopCh)
		c.connected.Store(false)
		disc := &packet.DisconnectPacket{}
		_ = c.writePacket(disc)
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})

	c.wg.Wait()
	return nil
}
