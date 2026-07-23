package snellv6

import (
	"bytes"
	"io"
	"testing"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
)

func TestShapedWriterWritePacketBufferFallsBackForInsufficientHeadroom(t *testing.T) {
	const inputHeadroom = 1024
	psk := []byte("snell-v6-packet-headroom-regression")
	profile := NewProfile(psk)
	payload := bytes.Repeat([]byte{0x42}, 64)
	sequence, _ := findShapedRecordRequiringHeadroom(t, profile, len(payload), inputHeadroom)

	salt := bytes.Repeat([]byte{0x24}, saltLen)
	writerCipher, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
	if err != nil {
		t.Fatal(err)
	}
	var upstream bytes.Buffer
	writer := newShapedWriter(
		&upstream,
		profile,
		salt,
		writerCipher,
		make([]byte, snell.NonceLen),
	)
	writer.saltSent = true
	writer.seq = sequence

	packet := buf.NewSize(inputHeadroom + len(payload) + snell.AEADTagLen)
	packet.Resize(inputHeadroom, 0)
	if _, err = packet.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = writer.WritePacketBuffer(packet); err != nil {
		t.Fatal(err)
	}
	if packet.RawCap() != 0 {
		t.Fatal("input packet was not released after the fallback write")
	}

	readerCipher, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
	if err != nil {
		t.Fatal(err)
	}
	reader := newShapedReader(bytes.NewReader(upstream.Bytes()), psk, profile)
	reader.cipher = readerCipher
	reader.seq = sequence
	record, err := reader.ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	defer record.Release()
	if !bytes.Equal(payload, record.Bytes()) {
		t.Fatalf("payload mismatch after fallback: got %d bytes, want %d", record.Len(), len(payload))
	}
}

func TestShapedWriterMakeBufferRecordUsesSufficientInputSpace(t *testing.T) {
	const inputHeadroom = 1024
	psk := []byte("snell-v6-packet-headroom-regression")
	profile := NewProfile(psk)
	payload := bytes.Repeat([]byte{0x24}, 64)
	sequence, requiredHeadroom := findShapedRecordRequiringHeadroom(t, profile, len(payload), inputHeadroom)

	salt := bytes.Repeat([]byte{0x42}, saltLen)
	writerCipher, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
	if err != nil {
		t.Fatal(err)
	}
	writer := newShapedWriter(
		io.Discard,
		profile,
		salt,
		writerCipher,
		make([]byte, snell.NonceLen),
	)
	writer.saltSent = true
	writer.seq = sequence

	packet := buf.NewSize(requiredHeadroom + len(payload) + snell.AEADTagLen)
	packet.Resize(requiredHeadroom, 0)
	if _, err = packet.Write(payload); err != nil {
		t.Fatal(err)
	}
	record := writer.makeBufferRecord(packet)
	if record != packet {
		record.Release()
		packet.Release()
		t.Fatal("sufficient input buffer unexpectedly used the allocating fallback")
	}
	record.Release()
}

func findShapedRecordRequiringHeadroom(t *testing.T, profile *Profile, payloadLen int, available int) (uint32, int) {
	t.Helper()
	for candidate := uint32(1); candidate < 10000; candidate++ {
		prefixLen := profile.recordPrefixLen(candidate)
		paddingLen := profile.paddingLen(candidate, payloadLen, prefixLen, 0, 0)
		frontLen := prefixLen + snell.HeaderCipherLen + paddingLen
		if frontLen > available {
			return candidate, frontLen
		}
	}
	t.Fatal("test profile did not produce a shaped record larger than the input headroom")
	return 0, 0
}
