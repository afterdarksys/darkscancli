package network

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Anomaly finding from the network analyzer.
type NetworkFinding struct {
	Severity    string
	Description string
	Protocol    string
	SourceIP    net.IP
	DestIP      net.IP
	SourcePort  uint16
	DestPort    uint16
	Timestamp   string
}

// NetworkAnalyzer struct inspects raw packets for anomalies matching C2 profiles.
type NetworkAnalyzer struct {
	// Threat intel feeds or ML models can be injected here.
	DnsBlocklist []string
}

// NewNetworkAnalyzer creates a new packet analyzer.
func NewNetworkAnalyzer(blocklist []string) *NetworkAnalyzer {
	return &NetworkAnalyzer{
		DnsBlocklist: blocklist,
	}
}

// AnalyzeStream reads from a packet channel and yields findings.
func (a *NetworkAnalyzer) AnalyzeStream(ctx context.Context, packets <-chan gopacket.Packet) <-chan NetworkFinding {
	findings := make(chan NetworkFinding, 100)

	go func() {
		defer close(findings)

		for {
			select {
			case <-ctx.Done():
				return
			case packet, ok := <-packets:
				if !ok {
					return
				}
				if finding, found := a.inspectPacket(packet); found {
					select {
					case findings <- finding:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return findings
}

func (a *NetworkAnalyzer) inspectPacket(packet gopacket.Packet) (NetworkFinding, bool) {
	// Look for IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}
	
	if ipLayer == nil {
		return NetworkFinding{}, false
	}

	var srcIP, dstIP net.IP
	if ip4, ok := ipLayer.(*layers.IPv4); ok {
		srcIP = ip4.SrcIP
		dstIP = ip4.DstIP
	} else if ip6, ok := ipLayer.(*layers.IPv6); ok {
		srcIP = ip6.SrcIP
		dstIP = ip6.DstIP
	}

	// Extract transport ports
	var srcPort, dstPort uint16
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}

	// Look for DNS requests
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		if !dns.QR { // It's a query
			for _, q := range dns.Questions {
				domain := string(q.Name)
				if a.isDomainBlocked(domain) {
					return NetworkFinding{
						Severity:    "HIGH",
						Description: fmt.Sprintf("DNS Query to known malicious domain: %s", domain),
						Protocol:    "DNS",
						SourceIP:    srcIP,
						DestIP:      dstIP,
						SourcePort:  srcPort,
						DestPort:    dstPort,
						Timestamp:   time.Now().UTC().Format(time.RFC3339),
					}, true
				}
			}
		}
	}

	return NetworkFinding{}, false
}

func (a *NetworkAnalyzer) isDomainBlocked(domain string) bool {
	for _, blocked := range a.DnsBlocklist {
		if domain == blocked || strings.HasSuffix(domain, "."+blocked) {
			return true
		}
	}
	return false
}
