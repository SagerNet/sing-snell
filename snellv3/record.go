package snellv3

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// snell-server v3.0.1: records are a sealed big-endian length followed by the
	// sealed payload; a length with no payload is the zero chunk, and server records
	// never exceed 0x3fff bytes.
	maxPayload      = snell.MaxPayloadLen
	lengthPlainLen  = 2
	lengthCipherLen = lengthPlainLen + snell.AEADTagLen
)

// snell-server v3.0.1: v1 clients seal records with ChaCha20-Poly1305 keyed by the
// full Argon2id output, while v2 and v3 clients use AES-128-GCM like later versions.
func newAEAD(psk []byte, salt []byte, chacha bool) (cipher.AEAD, error) {
	if !chacha {
		return snell.NewAEAD(snell.DeriveKey(psk, salt))
	}
	return chacha20poly1305.New(argon2.IDKey(psk, salt, 3, 8, 1, 32))
}

type reader struct {
	upstream        io.Reader
	psk             []byte
	chacha          bool
	cipher          cipher.AEAD
	nonce           []byte
	cache           *buf.Buffer
	readWaitOptions N.ReadWaitOptions
}

func (r *reader) initialize() error {
	if r.cipher != nil {
		return nil
	}
	salt := make([]byte, snell.SaltLen)
	_, err := io.ReadFull(r.upstream, salt)
	if err != nil {
		return err
	}
	aead, err := newAEAD(r.psk, salt, r.chacha)
	if err != nil {
		return err
	}
	r.cipher = aead
	r.nonce = make([]byte, snell.NonceLen)
	return nil
}

// snell-server v3.0.1: accepts both v1 ChaCha20-Poly1305 and v2/v3 AES-128-GCM
// clients on one port, trying AES-128-GCM on the first length first, and answers
// with the cipher the client used.
func readFirstRecord(upstream io.Reader, psk []byte) (*reader, *buf.Buffer, error) {
	salt := make([]byte, snell.SaltLen)
	_, err := io.ReadFull(upstream, salt)
	if err != nil {
		return nil, nil, err
	}
	var lengthCipher [lengthCipherLen]byte
	_, err = io.ReadFull(upstream, lengthCipher[:])
	if err != nil {
		return nil, nil, err
	}
	for _, chacha := range []bool{false, true} {
		recordReader := &reader{upstream: upstream, psk: psk, chacha: chacha, nonce: make([]byte, snell.NonceLen)}
		recordReader.cipher, err = newAEAD(psk, salt, chacha)
		if err != nil {
			return nil, nil, err
		}
		var lengthPlain [lengthPlainLen]byte
		_, err = recordReader.cipher.Open(lengthPlain[:0], recordReader.nonce, lengthCipher[:], nil)
		if err != nil {
			continue
		}
		snell.IncreaseNonce(recordReader.nonce)
		record, err := recordReader.readPayload(int(binary.BigEndian.Uint16(lengthPlain[:])))
		if err != nil {
			return nil, nil, err
		}
		return recordReader, record, nil
	}
	return nil, nil, E.Cause(err, "open record length")
}

func (r *reader) ReadRecord() (*buf.Buffer, error) {
	err := r.initialize()
	if err != nil {
		return nil, err
	}
	var lengthCipher [lengthCipherLen]byte
	_, err = io.ReadFull(r.upstream, lengthCipher[:])
	if err != nil {
		return nil, err
	}
	_, err = r.cipher.Open(lengthCipher[:0], r.nonce, lengthCipher[:], nil)
	if err != nil {
		return nil, E.Cause(err, "open record length")
	}
	snell.IncreaseNonce(r.nonce)
	return r.readPayload(int(binary.BigEndian.Uint16(lengthCipher[:lengthPlainLen])))
}

func (r *reader) readPayload(payloadLen int) (*buf.Buffer, error) {
	if payloadLen == 0 {
		return nil, io.EOF
	}
	if payloadLen > maxPayload {
		return nil, snell.ErrPayloadTooLarge
	}
	body := r.readWaitOptions.NewBufferSize(payloadLen + snell.AEADTagLen)
	_, err := body.ReadFullFrom(r.upstream, payloadLen+snell.AEADTagLen)
	if err != nil {
		body.Release()
		return nil, err
	}
	payloadCipher := body.Bytes()
	_, err = r.cipher.Open(payloadCipher[:0], r.nonce, payloadCipher, nil)
	if err != nil {
		body.Release()
		return nil, E.Cause(err, "open record payload")
	}
	snell.IncreaseNonce(r.nonce)
	body.Truncate(payloadLen)
	r.readWaitOptions.PostReturn(body)
	return body, nil
}

func (r *reader) NextRecord() (*buf.Buffer, error) {
	record := r.cache
	if record != nil {
		r.cache = nil
		if record.IsEmpty() {
			record.Release()
		} else {
			return record, nil
		}
	}
	return r.ReadRecord()
}

func (r *reader) SetCache(cache *buf.Buffer) {
	r.cache = cache
}

func (r *reader) ReleaseCache() {
	if r.cache != nil {
		r.cache.Release()
		r.cache = nil
	}
}

func (r *reader) Read(p []byte) (n int, err error) {
	for {
		if r.cache != nil {
			if r.cache.IsEmpty() {
				r.cache.Release()
				r.cache = nil
			} else {
				n = copy(p, r.cache.Bytes())
				r.cache.Advance(n)
				return
			}
		}
		r.cache, err = r.ReadRecord()
		if err != nil {
			return
		}
	}
}

func (r *reader) ReadBuffer(buffer *buf.Buffer) error {
	for {
		if r.cache != nil {
			if r.cache.IsEmpty() {
				r.cache.Release()
				r.cache = nil
			} else {
				n, _ := buffer.Write(r.cache.Bytes())
				r.cache.Advance(n)
				return nil
			}
		}
		var err error
		r.cache, err = r.ReadRecord()
		if err != nil {
			return err
		}
	}
}

func (r *reader) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	r.readWaitOptions = options
	return false
}

func (r *reader) WaitReadBuffer() (buffer *buf.Buffer, err error) {
	for {
		if r.cache == nil {
			return r.ReadRecord()
		}
		buffer = r.cache
		r.cache = nil
		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}
		if buffer.Start() >= r.readWaitOptions.FrontHeadroom && buffer.FreeLen() >= r.readWaitOptions.RearHeadroom {
			return
		}
		buffer = r.readWaitOptions.Copy(buffer)
		return buffer, nil
	}
}

func (r *reader) Upstream() any {
	return r.upstream
}

type writer struct {
	upstream io.Writer
	psk      []byte
	chacha   bool
	cipher   cipher.AEAD
	nonce    []byte
	salt     []byte
	saltSent bool
	access   sync.Mutex
}

func (w *writer) initialize() error {
	if w.cipher != nil {
		return nil
	}
	salt := make([]byte, snell.SaltLen)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return err
	}
	aead, err := newAEAD(w.psk, salt, w.chacha)
	if err != nil {
		return err
	}
	w.cipher = aead
	w.nonce = make([]byte, snell.NonceLen)
	w.salt = salt
	return nil
}

func (w *writer) saltLen() int {
	if w.saltSent {
		return 0
	}
	return snell.SaltLen
}

func (w *writer) sealLength(output []byte, payloadLen int) {
	binary.BigEndian.PutUint16(output[:lengthPlainLen], uint16(payloadLen))
	w.cipher.Seal(output[:0], w.nonce, output[:lengthPlainLen], nil)
	snell.IncreaseNonce(w.nonce)
}

func (w *writer) makeSliceRecordLocked(payload []byte) (*buf.Buffer, error) {
	err := w.initialize()
	if err != nil {
		return nil, err
	}
	if len(payload) > maxPayload {
		panic("snell: v3 record exceeds maximum")
	}
	payloadCipherLen := 0
	if len(payload) > 0 {
		payloadCipherLen = len(payload) + snell.AEADTagLen
	}
	saltLen := w.saltLen()
	out := buf.NewSize(saltLen + lengthCipherLen + payloadCipherLen)
	if saltLen > 0 {
		common.Must1(out.Write(w.salt))
		w.saltSent = true
	}
	w.sealLength(out.Extend(lengthCipherLen), len(payload))
	if len(payload) > 0 {
		payloadCipher := out.Extend(payloadCipherLen)
		w.cipher.Seal(payloadCipher[:0], w.nonce, payload, nil)
		snell.IncreaseNonce(w.nonce)
	}
	return out, nil
}

func (w *writer) makeBufferRecordLocked(buffer *buf.Buffer) (*buf.Buffer, error) {
	err := w.initialize()
	if err != nil {
		return nil, err
	}
	dataLen := buffer.Len()
	if dataLen == 0 || dataLen > maxPayload {
		panic("snell: invalid v3 buffer record length")
	}
	saltLen := w.saltLen()
	prefix := buffer.ExtendHeader(saltLen + lengthCipherLen)
	if saltLen > 0 {
		copy(prefix, w.salt)
		w.saltSent = true
	}
	w.sealLength(prefix[saltLen:], dataLen)
	payloadCipher := buffer.From(saltLen + lengthCipherLen)
	buffer.Extend(snell.AEADTagLen)
	w.cipher.Seal(payloadCipher[:0], w.nonce, payloadCipher[:dataLen], nil)
	snell.IncreaseNonce(w.nonce)
	return buffer, nil
}

func (w *writer) hasBufferHeadroom(buffer *buf.Buffer) bool {
	return buffer.Start() >= w.saltLen()+lengthCipherLen && buffer.FreeLen() >= snell.AEADTagLen
}

func (w *writer) writeRecordLocked(record *buf.Buffer) error {
	defer record.Release()
	return common.Error(w.upstream.Write(record.Bytes()))
}

func (w *writer) writeBytesLocked(p []byte) (n int, err error) {
	for len(p) > 0 {
		dataLen := min(len(p), maxPayload)
		var record *buf.Buffer
		record, err = w.makeSliceRecordLocked(p[:dataLen])
		if err != nil {
			return
		}
		err = w.writeRecordLocked(record)
		if err != nil {
			return
		}
		n += dataLen
		p = p[dataLen:]
	}
	return
}

func (w *writer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.access.Lock()
	defer w.access.Unlock()
	return w.writeBytesLocked(p)
}

func (w *writer) WriteBuffer(buffer *buf.Buffer) error {
	if buffer.IsEmpty() {
		buffer.Release()
		return nil
	}
	w.access.Lock()
	defer w.access.Unlock()
	err := w.initialize()
	if err != nil {
		buffer.Release()
		return err
	}
	if buffer.Len() > maxPayload || !w.hasBufferHeadroom(buffer) {
		_, err = w.writeBytesLocked(buffer.Bytes())
		buffer.Release()
		return err
	}
	record, err := w.makeBufferRecordLocked(buffer)
	if err != nil {
		buffer.Release()
		return err
	}
	return w.writeRecordLocked(record)
}

func (w *writer) WritePacketBuffer(buffer *buf.Buffer) error {
	if buffer.Len() > maxPayload {
		buffer.Release()
		return snell.ErrPayloadTooLarge
	}
	w.access.Lock()
	defer w.access.Unlock()
	err := w.initialize()
	if err != nil {
		buffer.Release()
		return err
	}
	if buffer.IsEmpty() || !w.hasBufferHeadroom(buffer) {
		record, err := w.makeSliceRecordLocked(buffer.Bytes())
		buffer.Release()
		if err != nil {
			return err
		}
		return w.writeRecordLocked(record)
	}
	record, err := w.makeBufferRecordLocked(buffer)
	if err != nil {
		buffer.Release()
		return err
	}
	return w.writeRecordLocked(record)
}

func (w *writer) WriteZeroChunk() error {
	w.access.Lock()
	defer w.access.Unlock()
	record, err := w.makeSliceRecordLocked(nil)
	if err != nil {
		return err
	}
	return w.writeRecordLocked(record)
}

func (w *writer) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(w.upstream)
	if !created {
		return nil, false
	}
	return w.CreateVectorisedWriterFor(upstreamWriter), true
}

func (w *writer) CreateVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter {
	return &vectorisedWriter{writer: w, upstream: upstream}
}

type vectorisedWriter struct {
	writer   *writer
	upstream N.VectorisedWriter
}

func (w *vectorisedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	var records []*buf.Buffer
	defer func() {
		buf.ReleaseMulti(records)
	}()
	recordWriter := w.writer
	recordWriter.access.Lock()
	defer recordWriter.access.Unlock()
	err := recordWriter.initialize()
	if err != nil {
		buf.ReleaseMulti(buffers)
		return err
	}
	for index, buffer := range buffers {
		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}
		if buffer.Len() <= maxPayload && recordWriter.hasBufferHeadroom(buffer) {
			record, err := recordWriter.makeBufferRecordLocked(buffer)
			if err != nil {
				buffer.Release()
				buf.ReleaseMulti(buffers[index+1:])
				return err
			}
			records = append(records, record)
			continue
		}
		for data := buffer.Bytes(); len(data) > 0; {
			recordLen := min(len(data), maxPayload)
			record, err := recordWriter.makeSliceRecordLocked(data[:recordLen])
			if err != nil {
				buffer.Release()
				buf.ReleaseMulti(buffers[index+1:])
				return err
			}
			records = append(records, record)
			data = data[recordLen:]
		}
		buffer.Release()
	}
	if len(records) == 0 {
		return nil
	}
	flushRecords := records
	records = nil
	return w.upstream.WriteVectorised(flushRecords)
}

func (w *writer) CreatePacketVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter {
	return &packetVectorisedWriter{writer: w, upstream: upstream}
}

type packetVectorisedWriter struct {
	writer   *writer
	upstream N.VectorisedWriter
}

func (w *packetVectorisedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	var records []*buf.Buffer
	defer func() {
		buf.ReleaseMulti(records)
	}()
	recordWriter := w.writer
	recordWriter.access.Lock()
	defer recordWriter.access.Unlock()
	err := recordWriter.initialize()
	if err != nil {
		buf.ReleaseMulti(buffers)
		return err
	}
	for index, buffer := range buffers {
		if buffer.Len() > maxPayload {
			buf.ReleaseMulti(buffers[index:])
			return snell.ErrPayloadTooLarge
		}
		var record *buf.Buffer
		if buffer.IsEmpty() || !recordWriter.hasBufferHeadroom(buffer) {
			record, err = recordWriter.makeSliceRecordLocked(buffer.Bytes())
			buffer.Release()
		} else {
			record, err = recordWriter.makeBufferRecordLocked(buffer)
		}
		if err != nil {
			buf.ReleaseMulti(buffers[index+1:])
			return err
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil
	}
	flushRecords := records
	records = nil
	return w.upstream.WriteVectorised(flushRecords)
}

func (w *writer) FrontHeadroom() int {
	if w.saltSent {
		return lengthCipherLen
	}
	return snell.SaltLen + lengthCipherLen
}

func (w *writer) RearHeadroom() int {
	return snell.AEADTagLen
}

func (w *writer) WriterMTU() int {
	return maxPayload
}

func (w *writer) Upstream() any {
	return w.upstream
}

var (
	_ reuse.RecordReader       = (*reader)(nil)
	_ reuse.RecordWriter       = (*writer)(nil)
	_ N.VectorisedWriter       = (*vectorisedWriter)(nil)
	_ N.VectorisedWriter       = (*packetVectorisedWriter)(nil)
	_ N.FrontHeadroom          = (*writer)(nil)
	_ N.RearHeadroom           = (*writer)(nil)
	_ N.WriterWithMTU          = (*writer)(nil)
	_ N.VectorisedWriteCreator = (*writer)(nil)
)
