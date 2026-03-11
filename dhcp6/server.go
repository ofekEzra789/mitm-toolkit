package dhcp6

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv6"
)

// What to do in this file //
// 1. Joining multicast group ff02::1:2 on port 547 to receive Solicits -> DONE
// 2. Listening for DHCPv6 packets from the victim -> DONE
// 3. Handling Solicit → send Advertise with preference=255 and offered IP
// 4. Handling Request → send Reply confirming the lease
// 5. Building and sending responses — Ethernet + IPv6 + UDP + DHCPv6 layers with correct options (ClientID, ServerID, IA_NA, DNS)

func ListenDHCPv6(ifaceName string, macAddr string, offeredIP net.IP) error {

	// Joining multicast group ff02::1:2 All DHCP Servers and Agents

	// need to listen (opening socket) first on port 547 udp - listen on all IPv6 interfaces on port 547 (DHCPv6 server port).
	conn, err := net.ListenPacket("udp6", "[::]:547")

	if err != nil {
		return fmt.Errorf("Failed to open connection on UDP port 547: %v", err)
	}

	defer conn.Close()

	// Joining the multicast group ff02::1:2
	p := ipv6.NewPacketConn(conn)

	iface, err := net.InterfaceByName(ifaceName) // -> get interface by name -> return the type i need (*net.Interface)

	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", ifaceName, err)
	}

	if err := p.JoinGroup(iface, &net.UDPAddr{IP: net.ParseIP("ff02::1:2")}); err != nil {
		return fmt.Errorf("failed to join multicast group: %v", err)
	}

	// create buffer
	buf := make([]byte, 65535)

	// receive new UDP packet (n -> It returns the number of bytes copied into) -- addr
	for {
		n, _, err := conn.ReadFrom(buf)

		if err != nil {
			continue
		}

		// need to parse buffer
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeDHCPv6, gopacket.Default)

		// extract the generic dhcpv6 Layer
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv6)
		
		if dhcpLayer == nil {
			continue
		}

		// Type assertion to get the exact layer with all the fields for dhcpv6
		dhcp, ok := dhcpLayer.(*layers.DHCPv6)

		if !ok {
			continue
		}

		// Switch case base on the message type
		switch dhcp.MsgType {

		case layers.DHCPv6MsgTypeSolicit:
			// Sending Advertise
			sendDHCPv6Response()

		case layers.DHCPv6MsgTypeRequest:
			//send Reply
			sendDHCPv6Response()
		}
	}

	return nil

}


// Sending response (Advertise / Reply)
func sendDHCPv6Response() {

}
