package dhcp

import (
	"fmt"
	"mitm-toolkit/network"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// on UDP port 67 -> DHCP server

func listenDHCP(iface network.NetworkInterface) error {
	
	// open interface to listen
	handle, err := pcap.OpenLive(
		iface.InterfaceName,
		65535,
		true,
		pcap.BlockForever,
	)

	if err != nil {
		return fmt.Errorf("Failed to open interface: %v", err)
	}

	defer handle.Close()

	// BPF filter -> capture packets going TO port 67 (going to the attacker)
	filter := "udp dst port 67"
	err = handle.SetBPFFilter(filter)

	if err != nil {
		return fmt.Errorf("failed to set BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {

		// extract the DHCP layer ipv4
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)

		if dhcpLayer != nil {
			dhcp, ok := dhcpLayer.(*layers.DHCPv4)

			if !ok {
				continue
			}

			for _, opt := range dhcp.Options {

				if opt.Type == layers.DHCPOptMessageType {
					
					switch layers.DHCPMsgType(opt.Data[0]) {

					case layers.DHCPMsgTypeDiscover:
						// client looking for DHCP server - we send offer


					case layers.DHCPMsgTypeRequest:
						// client accept offer -> we send ack

					}
					
					
				}

			}
		}

	}

	return nil

}