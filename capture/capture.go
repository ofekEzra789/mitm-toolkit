package capture

import (
	"fmt"
	"time"

	"mitm-toolkit/network"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func StartCapture(networkIface network.NetworkInterface, targetIP string) error {

	// Full packet
	handle, err := pcap.OpenLive(
		networkIface.InterfaceName,
		65535,
		true,
		pcap.BlockForever,
	)

	if err != nil {
		return fmt.Errorf("Failed to open interface: %v", err)
	}

	defer handle.Close()

	// BPF filter - HTTP, DNS, From/to the target IP
	filter := fmt.Sprintf("host %v and (port 80 or port 53)", targetIP)
	err = handle.SetBPFFilter(filter)

	if err != nil {
		return fmt.Errorf("failed to set BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Creating map (key is string and value is bool)
	seenQueries := make(map[string]bool)

	for packet := range packetSource.Packets() {

		// Check HTTP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {

			tcp := tcpLayer.(*layers.TCP)

			if tcp.SrcPort == 80 || tcp.DstPort == 80 {
				// This is http traffic

				payload := string(tcp.Payload)
				if len(payload) > 0 {
					ParseHTTP(payload)
				}
			}

		}

		// check DNS layer
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {

			dns := dnsLayer.(*layers.DNS)
			for _, question := range dns.Questions {
				query := string(question.Name)

				// Print only if not seen
				if !seenQueries[query] {
					color.Cyan("%-10s  %-16s %s\n", time.Now().Format("15:04:05"), "DNS", string(question.Name))
					seenQueries[query] = true
				}

			}

		}

	}

	return nil
}
