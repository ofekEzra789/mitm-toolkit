package dhcp6

// What to do in this file //
// 1. open the interface
// 2. Joining multicast group ff02::1:2 on port 547 to receive Solicits
// 3. Listening for DHCPv6 packets from the victim
// 4. Handling Solicit → send Advertise with preference=255 and offered IP
// 5. Handling Request → send Reply confirming the lease
// 6. Building and sending responses — Ethernet + IPv6 + UDP + DHCPv6 layers with correct options (ClientID, ServerID, IA_NA, DNS)

