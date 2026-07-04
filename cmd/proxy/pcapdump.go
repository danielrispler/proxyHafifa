package main

import (
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type pcapDump struct {
	mu sync.Mutex
	f  *os.File
	w  *pcapgo.Writer
}

func newPcapDump(path string, linkType layers.LinkType) (*pcapDump, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, linkType); err != nil {
		f.Close()
		return nil, err
	}
	return &pcapDump{f: f, w: w}, nil
}

func (d *pcapDump) writePacket(ci gopacket.CaptureInfo, data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.w.WritePacket(ci, data)
}

func (d *pcapDump) close() error {
	return d.f.Close()
}
