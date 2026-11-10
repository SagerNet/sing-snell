package snellv3

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	Version1 = 1
	Version2 = 2
	Version3 = 3
)

const (
	// snell-server v3.0.1: command-1 tunnels report upstream EOF before any payload
	// as ReplyError 0xff "end of file" and then close the connection.
	remoteEOFCode    = 0xff
	remoteEOFMessage = "end of file"
)

var (
	ErrUnknownVersion  = E.New("snell: unknown v1-v3 version")
	ErrReuseRequiresV2 = E.New("snell: reuse requires v2 or later")
	ErrUDPRequiresV3   = E.New("snell: udp requires v3")
)

type Client struct {
	version int
	psk     []byte
	reuse   bool
	obfs    snell.ObfsConfig
	dialer  N.Dialer
	server  M.Socksaddr

	pool      reuse.Pool[*reuseSession]
	closeIdle atomic.Bool
}

type ClientOptions struct {
	Version  int
	PSK      []byte
	Reuse    bool
	ObfsMode snell.ObfsMode
	ObfsHost string
	ObfsURI  string
	Dialer   N.Dialer
	Server   M.Socksaddr
}

func NewClient(options ClientOptions) (*Client, error) {
	switch options.Version {
	case Version1, Version2, Version3:
	default:
		return nil, E.Extend(ErrUnknownVersion, options.Version)
	}
	if len(options.PSK) == 0 {
		return nil, snell.ErrMissingPSK
	}
	if options.Reuse && options.Version == Version1 {
		return nil, ErrReuseRequiresV2
	}
	switch options.ObfsMode {
	case snell.ObfsModeNone, snell.ObfsModeHTTP, snell.ObfsModeTLS:
	default:
		return nil, E.New("snell: unknown obfs mode: ", int(options.ObfsMode))
	}
	client := &Client{
		version: options.Version,
		psk:     options.PSK,
		reuse:   options.Reuse,
		obfs:    snell.ObfsConfig{Mode: options.ObfsMode, Host: options.ObfsHost, URI: options.ObfsURI},
		dialer:  options.Dialer,
		server:  options.Server,
	}
	if options.Reuse {
		client.pool.Init()
	}
	return client, nil
}

func (c *Client) chacha() bool {
	return c.version == Version1
}

// snell-server v3.0.1: v1 clients open tunnels with command 1, which the server
// never reuses; v2 and v3 clients use command 5 so the connection can be reused.
func (c *Client) command() byte {
	if c.version == Version1 {
		return snell.CommandConnect
	}
	return snell.CommandConnectV2
}

func (c *Client) newReader(upstream io.Reader, readWaitOptions N.ReadWaitOptions) *reader {
	recordReader := &reader{upstream: upstream, psk: c.psk, chacha: c.chacha()}
	recordReader.InitializeReadWaiter(readWaitOptions)
	return recordReader
}

func (c *Client) newWriter(upstream io.Writer) *writer {
	return &writer{upstream: upstream, psk: c.psk, chacha: c.chacha()}
}

func (c *Client) DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	clientConn := &clientConn{client: c, Conn: c.obfs.ClientConn(conn), destination: destination}
	return clientConn, clientConn.writeRequest(nil)
}

func (c *Client) DialEarlyConn(conn net.Conn, destination M.Socksaddr) net.Conn {
	return &clientConn{client: c, Conn: c.obfs.ClientConn(conn), destination: destination}
}

func (c *Client) DialPacketConn(conn net.Conn) (N.NetPacketConn, error) {
	if c.version < Version3 {
		return nil, ErrUDPRequiresV3
	}
	return bufio.NewNetPacketConn(&clientPacketConn{Conn: c.obfs.ClientConn(conn), client: c}), nil
}

var _ snell.Method = (*Client)(nil)

// readReply parses the first record of a tunnel. A nil error with eof set means the
// tunnel ended before the target sent any payload.
func readReply(recordReader *reader, command byte) (cached *buf.Buffer, eof bool, err error) {
	record, err := recordReader.ReadRecord()
	if err != nil {
		// snell-server v3.0.1: command-5 tunnels answer upstream EOF before any
		// payload with a bare zero chunk instead of a reply.
		if command == snell.CommandConnectV2 && errors.Is(err, io.EOF) && recordReader.cipher != nil {
			return nil, true, nil
		}
		return nil, false, E.Cause(err, "read reply")
	}
	if command == snell.CommandConnect && isRemoteEOFReply(record) {
		record.Release()
		return nil, true, nil
	}
	cached, err = reuse.ParseReply(record)
	return cached, false, err
}

func isRemoteEOFReply(record *buf.Buffer) bool {
	reply := record.Bytes()
	return len(reply) == 3+len(remoteEOFMessage) &&
		reply[0] == snell.ReplyError && reply[1] == remoteEOFCode && int(reply[2]) == len(remoteEOFMessage) &&
		bytes.Equal(reply[3:], []byte(remoteEOFMessage))
}

type clientConn struct {
	net.Conn
	client      *Client
	destination M.Socksaddr

	access          sync.Mutex
	reader          *reader
	writer          *writer
	readWaitOptions N.ReadWaitOptions
	closeWriteOnce  sync.Once
	closeWriteErr   error
}

func (c *clientConn) writeRequest(payload []byte) error {
	requestPayload := snell.Request{Command: c.client.command(), Destination: c.destination}
	request := buf.NewSize(requestPayload.Len() + len(payload))
	err := requestPayload.Write(request)
	if err != nil {
		request.Release()
		return err
	}
	if len(payload) > 0 {
		common.Must1(request.Write(payload))
	}
	defer request.Release()

	// snell-server v3.0.1: only the first record is parsed as the request; a request
	// split across records resets the connection. The request is at most 516 bytes,
	// so it always fits in the first record.
	recordWriter := c.client.newWriter(c.Conn)
	_, err = recordWriter.Write(request.Bytes())
	if err != nil {
		return E.Cause(err, "write request")
	}
	c.writer = recordWriter
	return nil
}

func (c *clientConn) writeRequestBuffer(buffer *buf.Buffer) error {
	requestPayload := snell.Request{Command: c.client.command(), Destination: c.destination}
	request := buf.With(buffer.ExtendHeader(requestPayload.Len()))
	err := requestPayload.Write(request)
	if err != nil {
		buffer.Release()
		return err
	}
	recordWriter := c.client.newWriter(c.Conn)
	err = recordWriter.WriteBuffer(buffer)
	if err != nil {
		return E.Cause(err, "write request")
	}
	c.writer = recordWriter
	return nil
}

func (c *clientConn) readResponse() error {
	if c.reader != nil {
		return nil
	}
	recordReader := c.client.newReader(c.Conn, c.readWaitOptions)
	cached, eof, err := readReply(recordReader, c.client.command())
	if err != nil {
		return err
	}
	c.reader = recordReader
	if eof {
		return io.EOF
	}
	if cached != nil {
		recordReader.SetCache(cached)
	}
	return nil
}

func (c *clientConn) Read(p []byte) (int, error) {
	err := c.readResponse()
	if err != nil {
		return 0, err
	}
	return c.reader.Read(p)
}

func (c *clientConn) ReadBuffer(buffer *buf.Buffer) error {
	err := c.readResponse()
	if err != nil {
		return err
	}
	return c.reader.ReadBuffer(buffer)
}

func (c *clientConn) Write(p []byte) (int, error) {
	if c.writer != nil {
		return c.writer.Write(p)
	}
	c.access.Lock()
	if c.writer != nil {
		c.access.Unlock()
		return c.writer.Write(p)
	}
	defer c.access.Unlock()
	err := c.writeRequest(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *clientConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writer != nil {
		return c.writer.WriteBuffer(buffer)
	}
	c.access.Lock()
	if c.writer != nil {
		c.access.Unlock()
		return c.writer.WriteBuffer(buffer)
	}
	defer c.access.Unlock()
	return c.writeRequestBuffer(buffer)
}

func (c *clientConn) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(c.Conn)
	if !created {
		return nil, false
	}
	return &clientVectorisedWriter{conn: c, upstream: upstreamWriter}, true
}

type clientVectorisedWriter struct {
	conn     *clientConn
	upstream N.VectorisedWriter
}

func (w *clientVectorisedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	conn := w.conn
	if conn.writer != nil {
		return conn.writer.CreateVectorisedWriterFor(w.upstream).WriteVectorised(buffers)
	}
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
		err := conn.writeRequestBuffer(buffer)
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

// snell-server v3.0.1: a zero chunk half-closes the target for both command 1 and
// command 5, while a TCP FIN tears the whole tunnel down.
func (c *clientConn) CloseWrite() error {
	c.closeWriteOnce.Do(func() {
		c.access.Lock()
		defer c.access.Unlock()
		if c.writer == nil {
			c.closeWriteErr = c.writeRequest(nil)
			if c.closeWriteErr != nil {
				return
			}
		}
		c.closeWriteErr = c.writer.WriteZeroChunk()
	})
	return c.closeWriteErr
}

func (c *clientConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	if c.reader != nil {
		c.reader.InitializeReadWaiter(options)
	}
	return false
}

func (c *clientConn) WaitReadBuffer() (*buf.Buffer, error) {
	err := c.readResponse()
	if err != nil {
		return nil, err
	}
	return c.reader.WaitReadBuffer()
}

func (c *clientConn) CreateReadWaiter() (N.ReadWaiter, bool) {
	return c, true
}

func (c *clientConn) FrontHeadroom() int {
	if c.writer != nil {
		return c.writer.FrontHeadroom()
	}
	requestPayload := snell.Request{Command: c.client.command(), Destination: c.destination}
	return requestPayload.Len() + snell.SaltLen + lengthCipherLen
}

func (c *clientConn) RearHeadroom() int {
	return snell.AEADTagLen
}

func (c *clientConn) WriterMTU() int {
	return maxPayload
}

func (c *clientConn) NeedHandshakeForRead() bool {
	return c.reader == nil
}

func (c *clientConn) NeedHandshakeForWrite() bool {
	return c.writer == nil
}

func (c *clientConn) NeedAdditionalReadDeadline() bool {
	return c.reader == nil
}

func (c *clientConn) Upstream() any {
	return c.Conn
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.destination.TCPAddr()
}

var (
	_ N.ExtendedConn           = (*clientConn)(nil)
	_ N.ReadWaiter             = (*clientConn)(nil)
	_ N.ReadWaitCreator        = (*clientConn)(nil)
	_ N.VectorisedWriteCreator = (*clientConn)(nil)
	_ N.VectorisedWriter       = (*clientVectorisedWriter)(nil)
	_ N.EarlyReader            = (*clientConn)(nil)
	_ N.EarlyWriter            = (*clientConn)(nil)
	_ N.WriteCloser            = (*clientConn)(nil)
)
