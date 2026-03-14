# MITM Toolkit

A Man-in-the-Middle toolkit written in Go for educational purposes. Supports multiple attack modes including ARP cache poisoning, DHCP starvation, rogue DHCP server, and full IPv6 MITM (DHCPv6 + Rogue RA).

## Features

- **ARP Spoofing** - Bidirectional ARP cache poisoning to intercept traffic
- **DHCP Starvation** - Exhausts DHCP server IP pool by completing full DORA handshakes with random MACs
- **DHCP Rogue Server** - Responds to DHCP Discover/Request with crafted Offer/ACK, sets attacker as default gateway
- **DHCPv6 Rogue Server** - Responds to Solicit/Request with Advertise/Reply, preference 255 to win over legitimate server
- **Rogue Router Advertisement** - Sends ICMPv6 RA to set attacker as IPv6 default gateway
- **MITM6** - Combined DHCPv6 + Rogue RA for full IPv6 man-in-the-middle
- Real-time HTTP traffic monitoring (requests & responses)
- DNS query logging
- Automatic ARP table restoration on exit
- IP forwarding management

## Usage

### ARP Spoofing

```bash
sudo ./mitm -mode arp -t <target_ip>
```

### DHCP Starvation

```bash
sudo ./mitm -mode dhcp-starve -count <number_of_packets>
```

### DHCP Rogue Server

```bash
sudo ./mitm -mode dhcp -offer <ip_to_offer>
```

### Full DHCP Attack (Starvation + Rogue Server)

1. Run starvation: `sudo ./mitm -mode dhcp-starve -count <n>` (make sure count is enough to exhaust the DHCP pool)
2. Start rogue server: `sudo ./mitm -mode dhcp -offer <ip_to_offer>`
3. On target: `sudo dhclient -r && sudo dhclient`

> Make sure the target has `dhclient` installed (`apt install isc-dhcp-client`).

### DHCPv6 Rogue Server

```bash
sudo ./mitm -mode dhcpv6 -offer <ipv6_to_offer>
```

### Rogue Router Advertisement

```bash
sudo ./mitm -mode ra
```

### MITM6 (DHCPv6 + Rogue RA)

```bash
sudo ./mitm -mode mitm6 -offer <ipv6_to_offer>
```

Press `Ctrl+C` to stop.

## Requirements

- Linux (tested on Kali)
- Root privileges
- libpcap installed (`apt install libpcap-dev`)

## Project Structure

| Package | File | Purpose |
|---------|------|---------|
| `/` | `main.go` | Entry point, CLI flag parsing, mode selection |
| `network/` | `network.go` | Interface discovery, gateway detection, ARP resolution |
| `arp/` | `arp.go` | ARP spoofing, IP forwarding, ARP table restoration |
| `dhcp/` | `dhcp.go` | DHCP rogue server (listen, craft Offer/ACK packets) |
| `dhcp/` | `starvation.go` | DHCP starvation (full DORA with random MACs) |
| `dhcp6/` | `server.go` | DHCPv6 rogue server (Solicit→Advertise, Request→Reply) |
| `dhcp6/` | `ra.go` | Rogue Router Advertisement (ICMPv6 type 134) |
| `capture/` | `capture.go` | Packet capture, DNS monitoring |
| `capture/` | `http.go` | HTTP request/response parsing |

## Build

```bash
go build -buildvcs=false -o mitm .
```

> For educational use only. Only run against machines you own or have explicit permission to test.
