package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func StartCapture(networkInterface networkInterface, targetIP string) error {

	// Full packet
	handle, err := pcap.OpenLive(
		networkInterface.interfaceName,
		65535,
		true,
		pcap.BlockForever,
	)

	if err != nil {
		return fmt.Errorf("Faild to open interface: %v", err)
	}

	defer handle.Close()

	// BPF filter - HTTP, DNS, From/to the target IP
	filter := fmt.Sprintf("host %v and (port 80 or port 53)", targetIP)
	err = handle.SetBPFFilter(filter)

	if err != nil {
		return fmt.Errorf("failed to set BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {

		// Check HTTP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {

			tcp := tcpLayer.(*layers.TCP)

			if tcp.SrcPort == 80 || tcp.DstPort == 80 {
				// This is http traffic

				payload := string(tcp.Payload)
				if len(payload) > 0 {
					// Print to screen
					fmt.Printf("[HTTP] %v\n", payload)
				}
			}

		}

		// check DNS layer
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {

			dns := dnsLayer.(*layers.DNS)
			for _, question := range dns.Questions {
				fmt.Printf("[DNS] Query: %v\n", string(question.Name))
			}

		}

	}

	return nil
}
