package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
)

type networkInterface struct {
	interfaceName string
	ipv4Address   string
	macAddress    string
}

// Step 1: Identify your network interface
func GetLocalNetworkInfo() (networkInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return networkInterface{}, fmt.Errorf("failed to get interfaces: %v", err)
	}

	for _, iface := range interfaces {

		// Skip Loopback Interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var ipv4 string

		for _, addr := range addrs {
			// Parse IP Address
			ipNet, ok := addr.(*net.IPNet)

			if !ok {
				continue
			}

			// Check if it's IPv4 (not IPv6)
			if ipNet.IP.To4() != nil {
				ipv4 = ipNet.IP.String()
				break // Found IPv4, stop looking
			}
		}

		// Skip if no IPv4 found
		if ipv4 == "" {
			continue
		}

		// Get MAC address
		macAddr := iface.HardwareAddr.String()

		// Return the network interface info
		return networkInterface{
			interfaceName: iface.Name,
			ipv4Address:   ipv4,
			macAddress:    macAddr,
		}, nil
	}

	return networkInterface{}, fmt.Errorf("no valid network interface found")
}

// Step 2: Identify Network Gateway (Router IP)
func GetNetworkGateway() (string, error) {
	gatewayIP, err := gateway.DiscoverGateway()

	if err != nil {
		return "", fmt.Errorf("failed to discover gateway: %v", err)
	}

	return gatewayIP.String(), nil
}

// Step 4: Get MAC address from IP address using ARP
// Making ARP request to the default gateway

// IP source: .. , MAC source: ..
// IP Dest: .. , MAC dest: ff:ff:ff:ff:ff:ff (brodcast)
func GetMACFromIP(targetIP string, localInterface networkInterface) (string, error) {

	// Open network interface for packet capture
	handle, err := pcap.OpenLive(
		localInterface.interfaceName,
		1600,
		true,
		5*time.Second,
	)
	if err != nil {
		return "", fmt.Errorf("Faild to open interface: %v", err)
	}

	defer handle.Close()

	// Parse target IP address
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return "", fmt.Errorf("Invalid target IP: %v", targetIP)
	}

	// Parse local IP address (attacker ip address)
	srcIP := net.ParseIP(localInterface.ipv4Address)

	// Parse MAC address (attacker MAC address)
	srcMAC, err := net.ParseMAC(localInterface.macAddress)
	if err != nil {
		return "", fmt.Errorf("Invalid source MAC: %v", err)
	}

	// Broadcast MAC address
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// Building the Ethernet Layer
	eth := layers.Ethernet{
		SrcMAC:       srcMAC, // Attacker MAC address
		DstMAC:       dstMAC, // Brodcast MAC address
		EthernetType: layers.EthernetTypeARP,
	}

	// Building the ARP layer
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}

	// Serialize the Packet (Convert to raw bytes) -> Need to send raw bytes over the network
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err != nil {
		return "", fmt.Errorf("failed to serialize packet: %v", err)
	}

	// Set BPF Filter (before sending, so we don't miss the reply)
	filter := fmt.Sprintf("arp and src host %s", targetIP)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return "", fmt.Errorf("failed to set BPF filter: %v", err)
	}

	fmt.Printf("Resolving MAC address for %v...\n", targetIP)

	// Send the ARP Request
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		return "", fmt.Errorf("failed to send ARP request: %v", err)
	}

	// Read Packets and Find the Reply
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp, ok := arpLayer.(*layers.ARP)
			if !ok {
				continue
			}

			// Check if this is an ARP reply
			if arp.Operation == layers.ARPReply {
				// Extract MAC address
				mac := net.HardwareAddr(arp.SourceHwAddress)
				return mac.String(), nil
			}
		}
	}

	return "", fmt.Errorf("timeout: no ARP reply from %s", targetIP)

}
