package snellv5

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const maxUDPHeadroom = snell.SaltLen + snell.HeaderCipherLen + 1 + 1 + 255 + 2

type serverPacketConn struct {
	net.Conn
	service         *Service
	reader          reuse.RecordReader
	readWaitOptions N.ReadWaitOptions

	writeAccess sync.Mutex
	writer      reuse.RecordWriter
}

func (c *serverPacketConn) responseAddrLen(source M.Socksaddr) int {
	if source.Unwrap().Addr.Is4() {
		return 1 + 4 + 2
	}
	return 1 + 16 + 2
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	record, err := c.reader.NextRecord()
	if err != nil {
		return M.Socksaddr{}, err
	}
	command, err := record.ReadByte()
	if err != nil {
		record.Release()
		return M.Socksaddr{}, err
	}
	if command != snell.UDPCommandForward {
		record.Release()
		return M.Socksaddr{}, E.Extend(snell.ErrUnsupportedCommand, "udp ", command)
	}
	destination, err := c.readRequestPacketDestination(record)
	if err != nil {
		record.Release()
		return M.Socksaddr{}, err
	}
	if record.Len() > buffer.FreeLen() {
		record.Release()
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, err = buffer.Write(record.Bytes())
	record.Release()
	if err != nil {
		return M.Socksaddr{}, err
	}
	return destination, nil
}

func (c *serverPacketConn) readRequestPacketDestination(record *buf.Buffer) (M.Socksaddr, error) {
	first, err := record.ReadByte()
	if err != nil {
		return M.Socksaddr{}, err
	}
	if first != 0x00 {
		var host []byte
		host, err = record.ReadBytes(int(first))
		if err != nil {
			return M.Socksaddr{}, err
		}
		var portBytes []byte
		portBytes, err = record.ReadBytes(2)
		if err != nil {
			return M.Socksaddr{}, err
		}
		return M.ParseSocksaddrHostPort(string(host), binary.BigEndian.Uint16(portBytes)), nil
	}
	addressFamily, err := record.ReadByte()
	if err != nil {
		return M.Socksaddr{}, err
	}
	switch addressFamily {
	case snell.AddressTypeIPv4:
		var addressBytes []byte
		addressBytes, err = record.ReadBytes(4)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var portBytes []byte
		portBytes, err = record.ReadBytes(2)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var address [4]byte
		copy(address[:], addressBytes)
		return M.SocksaddrFrom(netip.AddrFrom4(address), binary.BigEndian.Uint16(portBytes)), nil
	case snell.AddressTypeIPv6:
		var addressBytes []byte
		addressBytes, err = record.ReadBytes(16)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var portBytes []byte
		portBytes, err = record.ReadBytes(2)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var address [16]byte
		copy(address[:], addressBytes)
		return M.SocksaddrFrom(netip.AddrFrom16(address), binary.BigEndian.Uint16(portBytes)).Unwrap(), nil
	default:
		// snell-server v5.0.1: FUN_00140a50 consumes the 0x00 marker and the
		// unknown address-family byte, then forwards the rest as payload with an
		// empty destination instead of aborting the UDP tunnel.
		return M.Socksaddr{}, nil
	}
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.writeAccess.Lock()
	if c.writer == nil {
		err := c.writeTunnelReply()
		if err != nil {
			c.writeAccess.Unlock()
			buffer.Release()
			return err
		}
	}
	recordWriter := c.writer
	c.writeAccess.Unlock()
	header := buf.With(buffer.ExtendHeader(c.responseAddrLen(destination)))
	err := snell.WriteUDPResponseAddress(header, destination)
	if err != nil {
		buffer.Release()
		return err
	}
	if buffer.Len() > maxPayload {
		buffer.Release()
		return snell.ErrPayloadTooLarge
	}
	return recordWriter.WritePacketBuffer(buffer)
}

func (c *serverPacketConn) writeTunnelReply() error {
	reply := [1]byte{snell.ReplyTunnel}
	if c.writer != nil {
		_, err := c.writer.Write(reply[:])
		if err != nil {
			return E.Cause(err, "write udp reply")
		}
		return nil
	}
	salt := make([]byte, snell.SaltLen)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return err
	}
	key := snell.DeriveKey(c.service.psk, salt)
	aead, err := snell.NewAEAD(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, snell.NonceLen)
	recordWriter, err := newWriter(c.Conn, aead, nonce)
	if err != nil {
		return err
	}
	err = recordWriter.WriteFirst(salt, reply[:])
	if err != nil {
		return E.Cause(err, "write udp reply")
	}
	c.writer = recordWriter
	return nil
}

func (c *serverPacketConn) FrontHeadroom() int {
	return maxUDPHeadroom
}

func (c *serverPacketConn) RearHeadroom() int {
	return snell.AEADTagLen
}

func (c *serverPacketConn) Upstream() any {
	return c.Conn
}

func (c *serverPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	c.reader.InitializeReadWaiter(options)
	return false
}

func (c *serverPacketConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	record, err := c.reader.WaitReadBuffer()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	command, err := record.ReadByte()
	if err != nil {
		record.Release()
		return nil, M.Socksaddr{}, err
	}
	if command != snell.UDPCommandForward {
		record.Release()
		return nil, M.Socksaddr{}, E.Extend(snell.ErrUnsupportedCommand, "udp ", command)
	}
	destination, err := c.readRequestPacketDestination(record)
	if err != nil {
		record.Release()
		return nil, M.Socksaddr{}, err
	}
	return record, destination, nil
}

var (
	_ N.PacketConn       = (*serverPacketConn)(nil)
	_ N.PacketReadWaiter = (*serverPacketConn)(nil)
)
