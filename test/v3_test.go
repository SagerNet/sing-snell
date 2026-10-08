package test

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv3"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var errV3RawZeroChunk = errors.New("snell v3 raw zero chunk")

type v3Server struct {
	name     string
	versions []int
	udp      bool
	start    func(t *testing.T, obfsMode snell.ObfsMode) string
}

func v3Servers() []v3Server {
	return []v3Server{
		{
			name:     "official-v2.0.6",
			versions: []int{snellv3.Version1, snellv3.Version2},
			start: func(t *testing.T, obfsMode snell.ObfsMode) string {
				return startOfficialV3Server(t, "v2", obfsMode)
			},
		},
		{
			name:     "official-v3.0.1",
			versions: []int{snellv3.Version1, snellv3.Version2, snellv3.Version3},
			udp:      true,
			start: func(t *testing.T, obfsMode snell.ObfsMode) string {
				return startOfficialV3Server(t, "v3", obfsMode)
			},
		},
		{
			name:     "local",
			versions: []int{snellv3.Version1, snellv3.Version2, snellv3.Version3},
			udp:      true,
			start:    startLocalV3Server,
		},
	}
}

func startOfficialV3Server(t *testing.T, version string, obfsMode snell.ObfsMode) string {
	port := freePort(t)
	config := v5Config(testPSK, port)
	if obfsMode != snell.ObfsModeNone {
		config += "obfs = " + obfsMode.String() + "\n"
	}
	startSnellServer(t, version, config, port)
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func startLocalV3Server(t *testing.T, obfsMode snell.ObfsMode) string {
	service, err := snellv3.NewService(snellv3.ServiceOptions{
		PSK:      []byte(testPSK),
		ObfsMode: obfsMode,
		Handler:  v3RouteHandler{},
	})
	require.NoError(t, err)
	return startLocalSnellService(t, service)
}

func newV3Client(t *testing.T, version int, obfsMode snell.ObfsMode, reuseServer string) *snellv3.Client {
	options := snellv3.ClientOptions{
		Version:  version,
		PSK:      []byte(testPSK),
		ObfsMode: obfsMode,
		ObfsHost: "obfs.example",
	}
	if reuseServer != "" {
		options.Reuse = true
		options.Dialer = N.SystemDialer
		options.Server = M.ParseSocksaddr(reuseServer)
	}
	client, err := snellv3.NewClient(options)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	return client
}

func TestV3ClientOptions(t *testing.T) {
	for _, version := range []int{0, 4, 5} {
		_, err := snellv3.NewClient(snellv3.ClientOptions{Version: version, PSK: []byte(testPSK)})
		require.ErrorIs(t, err, snellv3.ErrUnknownVersion, "version %d", version)
	}
	_, err := snellv3.NewClient(snellv3.ClientOptions{Version: snellv3.Version1, PSK: []byte(testPSK), Reuse: true})
	require.ErrorIs(t, err, snellv3.ErrReuseRequiresV2)
	for _, version := range []int{snellv3.Version1, snellv3.Version2} {
		client := newV3Client(t, version, snell.ObfsModeNone, "")
		_, err = client.DialPacketConn(nil)
		require.ErrorIs(t, err, snellv3.ErrUDPRequiresV3, "version %d", version)
	}
}

func TestV3TCP(t *testing.T) {
	for _, server := range v3Servers() {
		t.Run(server.name, func(t *testing.T) {
			address := server.start(t, snell.ObfsModeNone)
			closePort := startTCPCloseWithoutData(t)
			for _, version := range server.versions {
				label := fmt.Sprintf("%s-v%d", server.name, version)
				t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
					client := newV3Client(t, version, snell.ObfsModeNone, "")
					v3BulkEcho(t, client, address, label)
					v3VectorisedEcho(t, client, address, label)
					normalScenario{address: address, client: client}.HalfCloseEcho(t, label)

					serverConn, err := net.Dial("tcp", address)
					require.NoError(t, err)
					defer serverConn.Close()
					proxyConn, err := client.DialConn(serverConn, M.ParseSocksaddrHostPort("127.0.0.1", closePort))
					require.NoError(t, err)
					v3RemoteEOFWithoutData(t, proxyConn, label+"-remote-eof")
				})
			}
		})
	}
}

func TestV3TCPReuse(t *testing.T) {
	for _, server := range v3Servers() {
		t.Run(server.name, func(t *testing.T) {
			address := server.start(t, snell.ObfsModeNone)
			echoPort := startTCPHalfCloseEcho(t)
			delayedEchoPort := startTCPHalfCloseEcho(t, 750*time.Millisecond)
			tailEchoPort := startTCPHalfCloseTailEcho(t, 32*1024, 250*time.Millisecond)
			oversizedTailEchoPort := startTCPHalfCloseTailEcho(t, 0x80001, 250*time.Millisecond)
			closePort := startTCPCloseWithoutData(t)
			for _, version := range server.versions {
				if version < snellv3.Version2 {
					continue
				}
				label := fmt.Sprintf("%s-v%d-reuse", server.name, version)
				t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
					var proxy countingTCPProxy
					proxy.Start(t, address)
					client := newV3Client(t, version, snell.ObfsModeNone, proxy.address)

					scenario := reuseScenario{client: client, destination: M.ParseSocksaddrHostPort("127.0.0.1", echoPort)}
					delayedScenario := reuseScenario{client: client, destination: M.ParseSocksaddrHostPort("127.0.0.1", delayedEchoPort)}
					scenario.RoundTrip(t, label+"-1")
					scenario.RoundTrip(t, label+"-2")
					delayedScenario.CloseBeforeServerEOF(t, label+"-drain", time.Second)
					scenario.RoundTrip(t, label+"-after-drain")
					tailScenario := reuseScenario{client: client, destination: M.ParseSocksaddrHostPort("127.0.0.1", tailEchoPort)}
					tailScenario.CloseBeforeServerEOF(t, label+"-tail", 500*time.Millisecond)
					scenario.RoundTrip(t, label+"-after-tail")
					delayedScenario.CloseWhileReadBlocked(t, label+"-active-read-close")
					scenario.RoundTrip(t, label+"-after-active-read-close")

					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					proxyConn, err := client.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", closePort))
					require.NoError(t, err)
					v3RemoteEOFWithoutData(t, proxyConn, label+"-remote-eof")
					scenario.RoundTrip(t, label+"-after-remote-eof")
					require.Equal(t, int32(1), proxy.count.Load())

					oversizedTailScenario := reuseScenario{client: client, destination: M.ParseSocksaddrHostPort("127.0.0.1", oversizedTailEchoPort)}
					oversizedTailScenario.CloseBeforeServerEOF(t, label+"-oversized-tail", 500*time.Millisecond)
					scenario.RoundTrip(t, label+"-after-oversized-tail")
					require.Equal(t, int32(2), proxy.count.Load())
					scenario.ReadWaiter(t, label+"-read-waiter")
				})
			}
		})
	}
}

func TestV3Obfs(t *testing.T) {
	for _, obfsMode := range []snell.ObfsMode{snell.ObfsModeHTTP, snell.ObfsModeTLS} {
		t.Run(obfsMode.String(), func(t *testing.T) {
			for _, server := range v3Servers() {
				// snell-server v3.0.1: may leave responses after the first TLS obfs
				// record unframed, so TLS obfs only runs against the local server.
				if obfsMode == snell.ObfsModeTLS && server.name != "local" {
					continue
				}
				t.Run(server.name, func(t *testing.T) {
					address := server.start(t, obfsMode)
					echoPort := startTCPHalfCloseEcho(t)
					for _, version := range server.versions {
						label := fmt.Sprintf("%s-v%d-obfs-%s", server.name, version, obfsMode)
						t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
							client := newV3Client(t, version, obfsMode, "")
							v3BulkEcho(t, client, address, label)
							normalScenario{address: address, client: client}.HalfCloseEcho(t, label)
							if version < snellv3.Version2 {
								return
							}
							var proxy countingTCPProxy
							proxy.Start(t, address)
							reuseClient := newV3Client(t, version, obfsMode, proxy.address)
							scenario := reuseScenario{client: reuseClient, destination: M.ParseSocksaddrHostPort("127.0.0.1", echoPort)}
							scenario.RoundTrip(t, label+"-reuse-1")
							scenario.RoundTrip(t, label+"-reuse-2")
							require.Equal(t, int32(1), proxy.count.Load())
						})
					}
				})
			}
		})
	}
}

func TestV3UDP(t *testing.T) {
	for _, server := range v3Servers() {
		if !server.udp {
			continue
		}
		t.Run(server.name, func(t *testing.T) {
			address := server.start(t, snell.ObfsModeNone)
			echoPort := startUDPEcho(t)
			client := newV3Client(t, snellv3.Version3, snell.ObfsModeNone, "")
			serverConn, err := net.Dial("tcp", address)
			require.NoError(t, err)
			defer serverConn.Close()
			packetConn, err := client.DialPacketConn(serverConn)
			require.NoError(t, err)

			target := M.ParseSocksaddrHostPort("127.0.0.1", echoPort)
			for round := range 10 {
				v3PacketRoundTrip(t, packetConn, serverConn, target, target, fmt.Sprintf("%s round %d", server.name, round))
			}
			v3PacketRoundTrip(t, packetConn, serverConn, M.ParseSocksaddrHostPort("localhost", echoPort), target, server.name+" domain")
		})
	}
}

func TestV3UDPPacketBatchWriter(t *testing.T) {
	for _, server := range v3Servers() {
		if !server.udp {
			continue
		}
		t.Run(server.name, func(t *testing.T) {
			address := server.start(t, snell.ObfsModeNone)
			echoPort := startUDPEcho(t)
			client := newV3Client(t, snellv3.Version3, snell.ObfsModeNone, "")
			serverConn, err := net.Dial("tcp", address)
			require.NoError(t, err)
			defer serverConn.Close()
			packetConn, err := client.DialPacketConn(serverConn)
			require.NoError(t, err)
			batchWriter, created := bufio.CreatePacketBatchWriter(packetConn)
			require.True(t, created)

			target := M.ParseSocksaddrHostPort("127.0.0.1", echoPort)
			frontHeadroom := N.CalculateFrontHeadroom(packetConn)
			rearHeadroom := N.CalculateRearHeadroom(packetConn)
			messages := make([][]byte, 3)
			buffers := make([]*buf.Buffer, len(messages))
			destinations := make([]M.Socksaddr, len(messages))
			for index := range messages {
				messages[index] = make([]byte, 600+index*100)
				_, err = rand.Read(messages[index])
				require.NoError(t, err)
				buffer := buf.NewSize(frontHeadroom + len(messages[index]) + rearHeadroom)
				buffer.Resize(frontHeadroom, 0)
				_, err = buffer.Write(messages[index])
				require.NoError(t, err)
				buffers[index] = buffer
				destinations[index] = target
			}
			require.NoError(t, batchWriter.WritePacketBatch(buffers, destinations))

			received := make(map[string]bool)
			for range messages {
				readBuffer := make([]byte, 2048)
				require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(10*time.Second)))
				n, addr, readErr := packetConn.ReadFrom(readBuffer)
				require.NoError(t, readErr)
				require.Equal(t, target.String(), addr.String())
				received[string(readBuffer[:n])] = true
			}
			for index, message := range messages {
				require.True(t, received[string(message)], "message %d", index)
			}
		})
	}
}

func TestV3PingReplyClosesConnection(t *testing.T) {
	for _, server := range v3Servers() {
		t.Run(server.name, func(t *testing.T) {
			rawConn := dialV3Raw(t, server.start(t, snell.ObfsModeNone), false)
			rawConn.WriteRecord(t, []byte{snell.RequestVersion, snell.CommandPing, 0})
			reply, err := rawConn.ReadRecord(t)
			require.NoError(t, err)
			require.Equal(t, []byte{snell.ReplyPong}, reply)

			_, err = rawConn.ReadRecord(t)
			require.Error(t, err)
			require.False(t, errors.Is(err, errV3RawZeroChunk), "ping closes the connection instead of writing a zero chunk")
		})
	}
}

func TestV3CommandConnectClosesWithoutZeroChunkAfterReply(t *testing.T) {
	for _, server := range v3Servers() {
		t.Run(server.name, func(t *testing.T) {
			address := server.start(t, snell.ObfsModeNone)
			rawConn := dialV3Raw(t, address, true)
			payload := []byte("v3 legacy command connect")
			rawConn.WriteRecord(t, append(v3ConnectRequest(snell.CommandConnect, startTCPHalfCloseEcho(t)), payload...))
			rawConn.WriteRecord(t, nil)
			reply, err := rawConn.ReadRecord(t)
			require.NoError(t, err)
			require.Equal(t, append([]byte{snell.ReplyTunnel}, payload...), reply, "tunnel reply rides with the first payload")

			_, err = rawConn.ReadRecord(t)
			require.Error(t, err)
			require.False(t, errors.Is(err, errV3RawZeroChunk), "command 1 closes the TCP connection instead of writing a zero chunk")
		})
	}
}

func TestV3CommandConnectRemoteEOFWithoutData(t *testing.T) {
	for _, server := range v3Servers() {
		t.Run(server.name, func(t *testing.T) {
			address := server.start(t, snell.ObfsModeNone)
			rawConn := dialV3Raw(t, address, true)
			rawConn.WriteRecord(t, v3ConnectRequest(snell.CommandConnect, startTCPCloseWithoutData(t)))
			reply, err := rawConn.ReadRecord(t)
			require.NoError(t, err)
			require.Equal(t, append([]byte{snell.ReplyError, 0xff, 11}, "end of file"...), reply)

			_, err = rawConn.ReadRecord(t)
			require.Error(t, err)
			require.False(t, errors.Is(err, errV3RawZeroChunk))
		})
	}
}

func TestV3CommandConnectV2RemoteEOFWithoutDataKeepsSession(t *testing.T) {
	for _, server := range v3Servers() {
		t.Run(server.name, func(t *testing.T) {
			address := server.start(t, snell.ObfsModeNone)
			rawConn := dialV3Raw(t, address, false)
			rawConn.WriteRecord(t, v3ConnectRequest(snell.CommandConnectV2, startTCPCloseWithoutData(t)))
			_, err := rawConn.ReadRecord(t)
			require.ErrorIs(t, err, errV3RawZeroChunk, "command 5 answers remote EOF before data with a bare zero chunk")
			rawConn.WriteRecord(t, nil)

			payload := []byte("v3 second request")
			rawConn.WriteRecord(t, append(v3ConnectRequest(snell.CommandConnectV2, startTCPHalfCloseEcho(t)), payload...))
			rawConn.WriteRecord(t, nil)
			reply, err := rawConn.ReadRecord(t)
			require.NoError(t, err)
			require.Equal(t, append([]byte{snell.ReplyTunnel}, payload...), reply)
			_, err = rawConn.ReadRecord(t)
			require.ErrorIs(t, err, errV3RawZeroChunk)
		})
	}
}

func TestV3UDPDropsDatagramInRequestRecord(t *testing.T) {
	for _, server := range v3Servers() {
		if !server.udp {
			continue
		}
		t.Run(server.name, func(t *testing.T) {
			address := server.start(t, snell.ObfsModeNone)
			echoPort := startUDPEcho(t)
			packetHeader := []byte{snell.UDPCommandForward, 0x00, snell.AddressTypeIPv4, 127, 0, 0, 1}
			packetHeader = binary.BigEndian.AppendUint16(packetHeader, echoPort)

			rawConn := dialV3Raw(t, address, false)
			request := []byte{snell.RequestVersion, snell.CommandUDP, 0}
			request = append(request, packetHeader...)
			rawConn.WriteRecord(t, append(request, "fused"...))
			reply, err := rawConn.ReadRecord(t)
			require.NoError(t, err)
			require.Equal(t, []byte{snell.ReplyTunnel}, reply, "udp reply is written alone")

			rawConn.WriteRecord(t, append(append([]byte(nil), packetHeader...), "separate"...))
			response, err := rawConn.ReadRecord(t)
			require.NoError(t, err)
			expected := []byte{snell.AddressTypeIPv4, 127, 0, 0, 1}
			expected = binary.BigEndian.AppendUint16(expected, echoPort)
			require.Equal(t, append(expected, "separate"...), response, "datagram in the request record is dropped")
		})
	}
}

func v3BulkEcho(t *testing.T, client *snellv3.Client, address string, label string) {
	echoPort := startTCPEcho(t)
	serverConn, err := net.Dial("tcp", address)
	require.NoError(t, err)
	defer serverConn.Close()
	proxyConn, err := client.DialConn(serverConn, M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	require.NoError(t, err)

	payload := make([]byte, 1024*1024)
	_, err = rand.Read(payload)
	require.NoError(t, err)
	go func() {
		proxyConn.Write(payload)
	}()
	received := make([]byte, len(payload))
	require.NoError(t, proxyConn.SetReadDeadline(time.Now().Add(20*time.Second)))
	_, err = io.ReadFull(proxyConn, received)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, received), "%s payload mismatch", label)
}

func v3VectorisedEcho(t *testing.T, client *snellv3.Client, address string, label string) {
	echoPort := startTCPEcho(t)
	serverConn, err := net.Dial("tcp", address)
	require.NoError(t, err)
	defer serverConn.Close()
	proxyConn := client.DialEarlyConn(serverConn, M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	vectorisedWriter, created := bufio.CreateVectorisedWriter(proxyConn)
	require.True(t, created)

	parts := [][]byte{make([]byte, 700), make([]byte, 900), make([]byte, 20000)}
	var expected []byte
	frontHeadroom := N.CalculateFrontHeadroom(proxyConn)
	rearHeadroom := N.CalculateRearHeadroom(proxyConn)
	buffers := make([]*buf.Buffer, len(parts))
	for index, part := range parts {
		_, err = rand.Read(part)
		require.NoError(t, err)
		expected = append(expected, part...)
		buffer := buf.NewSize(frontHeadroom + len(part) + rearHeadroom)
		buffer.Resize(frontHeadroom, 0)
		_, err = buffer.Write(part)
		require.NoError(t, err)
		buffers[index] = buffer
	}
	require.NoError(t, vectorisedWriter.WriteVectorised(buffers))

	received := make([]byte, len(expected))
	require.NoError(t, proxyConn.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = io.ReadFull(proxyConn, received)
	require.NoError(t, err)
	require.True(t, bytes.Equal(expected, received), "%s vectorised payload mismatch", label)
}

func v3RemoteEOFWithoutData(t *testing.T, conn net.Conn, label string) {
	_, err := conn.Write([]byte(label))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	var one [1]byte
	n, err := conn.Read(one[:])
	require.Zero(t, n, label)
	require.ErrorIs(t, err, io.EOF, label)
	require.NoError(t, conn.Close(), label)
}

func v3PacketRoundTrip(t *testing.T, packetConn N.NetPacketConn, serverConn net.Conn, destination M.Socksaddr, source M.Socksaddr, label string) {
	message := make([]byte, 1200)
	_, err := rand.Read(message)
	require.NoError(t, err)
	_, err = packetConn.WriteTo(message, destination)
	require.NoError(t, err)
	received := make([]byte, 2048)
	require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(10*time.Second)))
	n, addr, err := packetConn.ReadFrom(received)
	require.NoError(t, err, label)
	require.Equal(t, source.String(), addr.String(), label)
	require.True(t, bytes.Equal(message, received[:n]), label)
}

func startTCPCloseWithoutData(t *testing.T) uint16 {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				N.CloseWrite(conn)
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

type v3RouteHandler struct {
	localRouteHandler
}

func (v3RouteHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err == nil {
			err = relayV3Packets(conn, upstream)
		}
		closeErr := conn.Close()
		if err == nil {
			err = closeErr
		}
		if onClose != nil {
			onClose(err)
		}
	}()
}

func relayV3Packets(conn N.PacketConn, upstream net.PacketConn) error {
	defer upstream.Close()
	go func() {
		for {
			packet := buf.NewSize(64 * 1024)
			packet.Resize(512, 0)
			n, addr, err := upstream.ReadFrom(packet.FreeBytes())
			if err != nil {
				packet.Release()
				return
			}
			packet.Truncate(n)
			err = conn.WritePacket(packet, M.SocksaddrFromNet(addr))
			if err != nil {
				return
			}
		}
	}()
	for {
		packet := buf.NewPacket()
		destination, err := conn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			return err
		}
		udpAddr, err := net.ResolveUDPAddr("udp4", destination.String())
		if err != nil {
			packet.Release()
			return err
		}
		_, err = upstream.WriteTo(packet.Bytes(), udpAddr)
		packet.Release()
		if err != nil {
			return err
		}
	}
}

func v3ConnectRequest(command byte, port uint16) []byte {
	host := "127.0.0.1"
	request := []byte{snell.RequestVersion, command, 0, byte(len(host))}
	request = append(request, host...)
	return binary.BigEndian.AppendUint16(request, port)
}

type v3RawConn struct {
	net.Conn
	psk           []byte
	chacha        bool
	requestAEAD   cipher.AEAD
	requestNonce  []byte
	responseAEAD  cipher.AEAD
	responseNonce []byte
}

func dialV3Raw(t *testing.T, address string, chacha bool) *v3RawConn {
	conn, err := net.Dial("tcp", address)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	return &v3RawConn{Conn: conn, psk: []byte(testPSK), chacha: chacha}
}

func (c *v3RawConn) newAEAD(t *testing.T, salt []byte) cipher.AEAD {
	if c.chacha {
		aead, err := chacha20poly1305.New(argon2.IDKey(c.psk, salt, 3, 8, 1, 32))
		require.NoError(t, err)
		return aead
	}
	aead, err := snell.NewAEAD(snell.DeriveKey(c.psk, salt))
	require.NoError(t, err)
	return aead
}

func (c *v3RawConn) WriteRecord(t *testing.T, payload []byte) {
	var wire []byte
	if c.requestAEAD == nil {
		salt := make([]byte, snell.SaltLen)
		_, err := rand.Read(salt)
		require.NoError(t, err)
		c.requestAEAD = c.newAEAD(t, salt)
		c.requestNonce = make([]byte, snell.NonceLen)
		wire = append(wire, salt...)
	}
	wire = c.requestAEAD.Seal(wire, c.requestNonce, binary.BigEndian.AppendUint16(nil, uint16(len(payload))), nil)
	snell.IncreaseNonce(c.requestNonce)
	if len(payload) > 0 {
		wire = c.requestAEAD.Seal(wire, c.requestNonce, payload, nil)
		snell.IncreaseNonce(c.requestNonce)
	}
	_, err := c.Conn.Write(wire)
	require.NoError(t, err)
}

func (c *v3RawConn) ReadRecord(t *testing.T) ([]byte, error) {
	if c.responseAEAD == nil {
		salt := make([]byte, snell.SaltLen)
		_, err := io.ReadFull(c.Conn, salt)
		if err != nil {
			return nil, err
		}
		c.responseAEAD = c.newAEAD(t, salt)
		c.responseNonce = make([]byte, snell.NonceLen)
	}
	lengthCipher := make([]byte, 2+snell.AEADTagLen)
	_, err := io.ReadFull(c.Conn, lengthCipher)
	if err != nil {
		return nil, err
	}
	length, err := c.responseAEAD.Open(nil, c.responseNonce, lengthCipher, nil)
	require.NoError(t, err)
	snell.IncreaseNonce(c.responseNonce)
	payloadLen := int(binary.BigEndian.Uint16(length))
	if payloadLen == 0 {
		return nil, errV3RawZeroChunk
	}
	require.LessOrEqual(t, payloadLen, snell.MaxPayloadLen)
	payloadCipher := make([]byte, payloadLen+snell.AEADTagLen)
	_, err = io.ReadFull(c.Conn, payloadCipher)
	if err != nil {
		return nil, err
	}
	payload, err := c.responseAEAD.Open(nil, c.responseNonce, payloadCipher, nil)
	require.NoError(t, err)
	snell.IncreaseNonce(c.responseNonce)
	return payload, nil
}
