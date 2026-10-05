// Offline inventory of a classic PCAP file. It does not open a capture device.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	maxPackets = 10000
	maxBytes   = 8 << 20
)

type Inventory struct {
	Packets       int    `json:"packets"`
	IncludedBytes int    `json:"included_bytes"`
	LinkType      int    `json:"link_type"`
	Truncated     bool   `json:"truncated"`
	StopReason    string `json:"stop_reason"`
}

func ReadInventory(r io.Reader) (Inventory, error) {
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return Inventory{}, fmt.Errorf("pcap header: %w", err)
	}
	var order binary.ByteOrder
	switch binary.LittleEndian.Uint32(header[:4]) {
	case 0xA1B2C3D4:
		order = binary.LittleEndian
	default:
		if binary.BigEndian.Uint32(header[:4]) == 0xA1B2C3D4 {
			order = binary.BigEndian
			break
		}
		return Inventory{}, fmt.Errorf("classic pcap magic required")
	}
	result := Inventory{LinkType: int(order.Uint32(header[20:24])), StopReason: "end"}
	record := make([]byte, 16)
	for {
		if result.Packets >= maxPackets {
			result.Truncated = true
			result.StopReason = "packet budget"
			return result, nil
		}
		_, err := io.ReadFull(r, record)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return result, nil
		}
		if err != nil {
			return Inventory{}, err
		}
		size := int(order.Uint32(record[8:12]))
		if size > 65535 {
			return Inventory{}, fmt.Errorf("packet length %d is outside the capture bound", size)
		}
		if result.IncludedBytes+size > maxBytes {
			result.Truncated = true
			result.StopReason = "byte budget"
			return result, nil
		}
		if _, err := io.CopyN(io.Discard, r, int64(size)); err != nil {
			return Inventory{}, fmt.Errorf("packet body: %w", err)
		}
		result.Packets++
		result.IncludedBytes += size
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sensor <capture.pcap>")
		os.Exit(2)
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer file.Close()
	result, err := ReadInventory(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded, _ := json.Marshal(result)
	fmt.Println(string(encoded))
}
