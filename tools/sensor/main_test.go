package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func pcap(packets ...[]byte) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0xA1B2C3D4))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(4))
	_ = binary.Write(&buf, binary.LittleEndian, int32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	for _, packet := range packets {
		_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(packet)))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(packet)))
		buf.Write(packet)
	}
	return buf.Bytes()
}

func TestInventoryCountsPacketsWithoutReturningThem(t *testing.T) {
	result, err := ReadInventory(bytes.NewReader(pcap([]byte("secret-payload"))))
	if err != nil {
		t.Fatal(err)
	}
	if result.Packets != 1 || result.IncludedBytes != len("secret-payload") || result.Truncated {
		t.Fatalf("%+v", result)
	}
	encoded := result.StopReason + string(rune(result.LinkType))
	if encoded == "secret-payload" {
		t.Fatal("inventory must not echo packet bytes")
	}
}

func TestInventoryStopsAtTheByteBudget(t *testing.T) {
	// The byte budget has to be crossed with realistic records. A single packet
	// larger than 65535 bytes cannot occur in a capture, so building one to hit
	// the budget would trip the single-record guard instead and never exercise
	// the budget at all.
	const recordMax = 65535
	body := make([]byte, recordMax)
	packets := make([][]byte, 0, maxBytes/recordMax+2)
	expected := 0
	included := 0
	for included+recordMax <= maxBytes {
		packets = append(packets, body)
		included += recordMax
		expected++
	}
	// A final record sized to exceed whatever budget remains, so truncation is
	// reached regardless of how the division leaves the remainder.
	remaining := maxBytes - included
	oversize := remaining + 1
	if oversize > recordMax {
		t.Fatalf("remaining budget %d cannot be exceeded by one record", remaining)
	}
	packets = append(packets, make([]byte, oversize))

	result, err := ReadInventory(bytes.NewReader(pcap(packets...)))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Truncated || result.StopReason != "byte budget" {
		t.Fatalf("expected truncation at the byte budget, got %+v", result)
	}
	if result.Packets != expected {
		t.Fatalf("counted %d packets, want %d", result.Packets, expected)
	}
	if result.IncludedBytes != included {
		t.Fatalf("counted %d bytes, want %d", result.IncludedBytes, included)
	}
}

func TestInventoryRejectsAnImpossibleRecordLength(t *testing.T) {
	// A record claiming more than a capture can hold is malformed, and is
	// rejected rather than allocated or skipped.
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0xA1B2C3D4))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(4))
	_ = binary.Write(&buf, binary.LittleEndian, int32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1<<20))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1<<20))

	if _, err := ReadInventory(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("expected an error for an oversized record length")
	}
}
