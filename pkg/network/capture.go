package network

import (
	"context"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// CaptureOptions defines the configuration for a network capture session.
type CaptureOptions struct {
	Interface string
	Promiscuous bool
	SnapshotLen int32
	Timeout time.Duration
	BPFFilter string
}

// PacketCapturer provides an OS-agnostic interface for capturing traffic.
type PacketCapturer interface {
	Start(ctx context.Context) (<-chan gopacket.Packet, error)
	Stop() error
	Stats() (CaptureStats, error)
}

// CaptureStats holds metrics about the capture session.
type CaptureStats struct {
	PacketsReceived int
	PacketsDropped  int
}

// PCAPCapturer implements PacketCapturer using libpcap.
type PCAPCapturer struct {
	opts   CaptureOptions
	handle *pcap.Handle
	// done   chan struct{}
}

// NewPCAPCapturer creates a new PCAP-based packet capturer.
func NewPCAPCapturer(opts CaptureOptions) (*PCAPCapturer, error) {
	if opts.SnapshotLen == 0 {
		opts.SnapshotLen = 65535
	}
	if opts.Timeout == 0 {
		opts.Timeout = 1 * time.Second
	}

	return &PCAPCapturer{
		opts: opts,
	}, nil
}

// Start opens the network interface and starts capturing packets.
// The returned channel is closed when ctx is cancelled or Stop is called.
func (c *PCAPCapturer) Start(ctx context.Context) (<-chan gopacket.Packet, error) {
	handle, err := pcap.OpenLive(c.opts.Interface, c.opts.SnapshotLen, c.opts.Promiscuous, c.opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to open device %s: %w", c.opts.Interface, err)
	}

	if c.opts.BPFFilter != "" {
		if err := handle.SetBPFFilter(c.opts.BPFFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	c.handle = handle
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Close the handle when ctx is cancelled so the packet channel is drained
	// and the goroutine inside PacketSource exits cleanly.
	go func() {
		<-ctx.Done()
		c.Stop() //nolint:errcheck
	}()

	return packetSource.Packets(), nil
}

// Stop halts the capture session.
func (c *PCAPCapturer) Stop() error {
	if c.handle != nil {
		c.handle.Close()
		c.handle = nil
	}
	return nil
}

// Stats returns the capture metrics.
func (c *PCAPCapturer) Stats() (CaptureStats, error) {
	if c.handle == nil {
		return CaptureStats{}, fmt.Errorf("capturer not running")
	}
	stats, err := c.handle.Stats()
	if err != nil {
		return CaptureStats{}, err
	}
	return CaptureStats{
		PacketsReceived: stats.PacketsReceived,
		PacketsDropped:  stats.PacketsDropped,
	}, nil
}
