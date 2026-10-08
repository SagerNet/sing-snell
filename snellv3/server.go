package snellv3

import (
	"context"
	"io"
	"net"
	"sync"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Service serves v1, v2 and v3 clients on one listener like snell-server v3.0.1.
type Service struct {
	psk     []byte
	obfs    snell.ObfsConfig
	handler snell.Handler
}

type ServiceOptions struct {
	PSK      []byte
	ObfsMode snell.ObfsMode
	Handler  snell.Handler
}

func NewService(options ServiceOptions) (*Service, error) {
	if len(options.PSK) == 0 {
		return nil, snell.ErrMissingPSK
	}
	switch options.ObfsMode {
	case snell.ObfsModeNone, snell.ObfsModeHTTP, snell.ObfsModeTLS:
	default:
		return nil, E.New("snell: unknown obfs mode: ", int(options.ObfsMode))
	}
	return &Service{
		psk:     options.PSK,
		obfs:    snell.ObfsConfig{Mode: options.ObfsMode},
		handler: options.Handler,
	}, nil
}

func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	err := s.newConnection(ctx, conn, source, onClose)
	if err != nil {
		return &snell.ServerError{Conn: conn, Source: source, Cause: err}
	}
	return nil
}

// newWriter answers with a fresh salt, sealed with the cipher the client chose.
func (s *Service) newWriter(upstream io.Writer, recordReader *reader) *writer {
	return &writer{upstream: upstream, psk: s.psk, chacha: recordReader.chacha}
}

func (s *Service) readRequest(record *buf.Buffer) (snell.Request, error) {
	prefix := make([]byte, 3)
	_, err := io.ReadFull(record, prefix)
	if err != nil {
		return snell.Request{}, err
	}
	if prefix[0] != snell.RequestVersion {
		return snell.Request{}, E.Extend(snell.ErrBadVersion, "request version ", prefix[0])
	}
	request := snell.Request{Command: prefix[1]}
	if request.Command == snell.CommandPing {
		return request, nil
	}
	// snell-server v3.0.1: accepts and ignores a non-empty client id.
	clientIDLen := int(prefix[2])
	if clientIDLen > 0 {
		request.ClientID = make([]byte, clientIDLen)
		_, err = io.ReadFull(record, request.ClientID)
		if err != nil {
			return snell.Request{}, err
		}
	}
	switch request.Command {
	case snell.CommandConnect, snell.CommandConnectV2:
		request.Destination, err = snell.ReadConnectAddress(record)
		if err != nil {
			return snell.Request{}, err
		}
	case snell.CommandUDP:
	default:
		return snell.Request{}, E.Extend(snell.ErrUnsupportedCommand, request.Command)
	}
	return request, nil
}

func (s *Service) newConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	conn = s.obfs.ServerConn(conn)
	recordReader, record, err := readFirstRecord(conn, s.psk)
	if err != nil {
		return E.Cause(err, "read request")
	}
	request, err := s.readRequest(record)
	if err != nil {
		record.Release()
		return E.Cause(err, "decode request")
	}

	switch request.Command {
	case snell.CommandConnect:
		serverConn := &serverConn{Conn: conn, service: s, reader: recordReader}
		if record.IsEmpty() {
			record.Release()
		} else {
			recordReader.SetCache(record)
		}
		s.handler.NewConnectionEx(ctx, serverConn, source, request.Destination, onClose)
		return nil
	case snell.CommandConnectV2:
		reuseSession := &serverReuseSession{Conn: conn, service: s, reader: recordReader}
		return reuseSession.Serve(ctx, source, onClose, record, request)
	case snell.CommandUDP:
		// snell-server v3.0.1: datagrams sharing the first record with the UDP
		// request are dropped.
		record.Release()
		return s.newPacketConnection(ctx, &serverPacketConn{Conn: conn, service: s, reader: recordReader}, source, onClose)
	case snell.CommandPing:
		record.Release()
		err = s.writePong(conn, recordReader, nil)
		closeErr := conn.Close()
		if err != nil {
			return err
		}
		return closeErr
	default:
		record.Release()
		return E.Extend(snell.ErrUnsupportedCommand, request.Command)
	}
}

func (s *Service) newPacketConnection(ctx context.Context, packetConn *serverPacketConn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	// snell-server v3.0.1: writes the UDP tunnel reply in its own record as soon as
	// the request is accepted.
	err := packetConn.writeTunnelReply()
	if err != nil {
		return err
	}
	firstPacket := buf.NewPacket()
	destination, err := packetConn.ReadPacket(firstPacket)
	if err != nil {
		firstPacket.Release()
		return E.Cause(err, "read first packet")
	}
	s.handler.NewPacketConnectionEx(ctx, bufio.NewCachedPacketConn(packetConn, firstPacket, destination), source, destination, onClose)
	return nil
}

// snell-server v3.0.1: answers ping with a single PONG record and closes.
func (s *Service) writePong(conn net.Conn, recordReader *reader, recordWriter *writer) error {
	if recordWriter == nil {
		recordWriter = s.newWriter(conn, recordReader)
	}
	pong := [1]byte{snell.ReplyPong}
	_, err := recordWriter.Write(pong[:])
	return err
}

var _ snell.Service = (*Service)(nil)

func writeReplyPayload(recordWriter *writer, payload []byte) error {
	first := payload
	if len(first) > maxPayload-1 {
		first = payload[:maxPayload-1]
	}
	reply := buf.NewSize(1 + len(first))
	common.Must(reply.WriteByte(snell.ReplyTunnel))
	common.Must1(reply.Write(first))
	_, err := recordWriter.Write(reply.Bytes())
	reply.Release()
	if err != nil {
		return E.Cause(err, "write reply")
	}
	if len(payload) > len(first) {
		_, err = recordWriter.Write(payload[len(first):])
	}
	return err
}

func writeReplyBuffer(recordWriter *writer, buffer *buf.Buffer) error {
	buffer.ExtendHeader(1)[0] = snell.ReplyTunnel
	err := recordWriter.WriteBuffer(buffer)
	if err != nil {
		return E.Cause(err, "write reply")
	}
	return nil
}

func writeErrorReply(recordWriter *writer, code byte, message string) error {
	reply := buf.NewSize(3 + len(message))
	defer reply.Release()
	common.Must(reply.WriteByte(snell.ReplyError))
	common.Must(reply.WriteByte(code))
	common.Must(reply.WriteByte(byte(len(message))))
	common.Must1(reply.WriteString(message))
	_, err := recordWriter.Write(reply.Bytes())
	if err != nil {
		return E.Cause(err, "write error reply")
	}
	return nil
}

type serverConn struct {
	net.Conn
	service *Service
	reader  *reader

	access sync.Mutex
	writer *writer

	closeWriteOnce sync.Once
	closeWriteErr  error
}

// snell-server v3.0.1: the tunnel reply is deferred until the target sends data and
// travels in the same record as the first payload.
func (c *serverConn) writeResponse(payload []byte) error {
	recordWriter := c.service.newWriter(c.Conn, c.reader)
	err := writeReplyPayload(recordWriter, payload)
	if err != nil {
		return err
	}
	c.writer = recordWriter
	return nil
}

func (c *serverConn) writeResponseBuffer(buffer *buf.Buffer) error {
	recordWriter := c.service.newWriter(c.Conn, c.reader)
	err := writeReplyBuffer(recordWriter, buffer)
	if err != nil {
		return err
	}
	c.writer = recordWriter
	return nil
}

func (c *serverConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *serverConn) ReadBuffer(buffer *buf.Buffer) error {
	return c.reader.ReadBuffer(buffer)
}

func (c *serverConn) Write(p []byte) (int, error) {
	c.access.Lock()
	if c.writer != nil {
		recordWriter := c.writer
		c.access.Unlock()
		return recordWriter.Write(p)
	}
	defer c.access.Unlock()
	err := c.writeResponse(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	c.access.Lock()
	if c.writer != nil {
		recordWriter := c.writer
		c.access.Unlock()
		return recordWriter.WriteBuffer(buffer)
	}
	defer c.access.Unlock()
	return c.writeResponseBuffer(buffer)
}

func (c *serverConn) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(c.Conn)
	if !created {
		return nil, false
	}
	return &serverVectorisedWriter{conn: c, upstream: upstreamWriter}, true
}

type serverVectorisedWriter struct {
	conn     *serverConn
	upstream N.VectorisedWriter
}

func (w *serverVectorisedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	conn := w.conn
	conn.access.Lock()
	if conn.writer != nil {
		recordWriter := conn.writer
		conn.access.Unlock()
		return recordWriter.CreateVectorisedWriterFor(w.upstream).WriteVectorised(buffers)
	}
	for index, buffer := range buffers {
		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}
		err := conn.writeResponseBuffer(buffer)
		if err != nil {
			conn.access.Unlock()
			buf.ReleaseMulti(buffers[index+1:])
			return err
		}
		if index+1 < len(buffers) {
			recordWriter := conn.writer
			conn.access.Unlock()
			return recordWriter.CreateVectorisedWriterFor(w.upstream).WriteVectorised(buffers[index+1:])
		}
		conn.access.Unlock()
		return nil
	}
	conn.access.Unlock()
	return nil
}

func (c *serverConn) CloseWrite() error {
	c.closeWriteOnce.Do(func() {
		c.access.Lock()
		defer c.access.Unlock()
		if c.writer == nil {
			// snell-server v3.0.1: command-1 upstream EOF before any payload is
			// reported as ReplyError 0xff "end of file" before closing.
			c.writer = c.service.newWriter(c.Conn, c.reader)
			c.closeWriteErr = writeErrorReply(c.writer, remoteEOFCode, remoteEOFMessage)
		}
		// snell-server v3.0.1: command-1 tunnels close on upstream EOF instead of
		// writing a zero chunk.
		closeErr := c.Conn.Close()
		if c.closeWriteErr == nil {
			c.closeWriteErr = closeErr
		}
	})
	return c.closeWriteErr
}

func (c *serverConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return c.reader.InitializeReadWaiter(options)
}

func (c *serverConn) WaitReadBuffer() (*buf.Buffer, error) {
	return c.reader.WaitReadBuffer()
}

func (c *serverConn) FrontHeadroom() int {
	if c.writer != nil {
		return c.writer.FrontHeadroom()
	}
	return 1 + snell.SaltLen + lengthCipherLen
}

func (c *serverConn) RearHeadroom() int {
	return snell.AEADTagLen
}

func (c *serverConn) WriterMTU() int {
	return maxPayload
}

func (c *serverConn) Upstream() any {
	return c.Conn
}

var (
	_ N.ExtendedConn           = (*serverConn)(nil)
	_ N.ReadWaiter             = (*serverConn)(nil)
	_ N.VectorisedWriteCreator = (*serverConn)(nil)
	_ N.VectorisedWriter       = (*serverVectorisedWriter)(nil)
	_ N.WriteCloser            = (*serverConn)(nil)
)
