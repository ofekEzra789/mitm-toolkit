# MITM Toolkit

A Man-in-the-Middle toolkit written in Go for educational purposes. Supports multiple attack modes including ARP cache poisoning and DHCP rogue server.

## Features

- **ARP Spoofing** - Bidirectional ARP cache poisoning to intercept traffic
- **DHCP Rogue Server** - Responds to DHCP Discover/Request with crafted Offer/ACK, sets attacker as default gateway
- Real-time HTTP traffic monitoring (requests & responses)
- DNS query logging
- Automatic ARP table restoration on exit
- IP forwarding management

## Usage

### ARP Spoofing

```bash
sudo ./mitm -mode arp -t <target_ip>
```

### DHCP Rogue Server

```bash
sudo ./mitm -mode dhcp -offer <ip_to_offer>
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
| `capture/` | `capture.go` | Packet capture, DNS monitoring |
| `capture/` | `http.go` | HTTP request/response parsing |

## Build

```bash
go build -buildvcs=false -o mitm .
```

> For educational use only. Only run against machines you own or have explicit permission to test.
