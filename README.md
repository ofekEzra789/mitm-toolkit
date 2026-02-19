# MITM ARP Spoofing Tool

A Man-in-the-Middle tool written in Go for educational purposes. Performs ARP cache poisoning to intercept and monitor network traffic between a target and its gateway.

## Features

- ARP cache poisoning (bidirectional)
- Real-time HTTP traffic monitoring (requests & responses)
- DNS query logging
- Automatic ARP table restoration on exit

## Usage

```bash
sudo ./mitm -t <target_ip>
```

Press `Ctrl+C` to stop and restore ARP tables.

## Requirements

- Linux (tested on Kali)
- Root privileges
- libpcap installed (`apt install libpcap-dev`)

## Project Structure

| File | Purpose |
|------|---------|
| `main.go` | Entry point, orchestration |
| `network.go` | Interface discovery, ARP resolution |
| `attack.go` | ARP spoofing, IP forwarding, cleanup |
| `capture.go` | Packet capture, HTTP/DNS monitoring |
| `utils.go` | HTTP parsing helpers |

## Build

```bash
go build -buildvcs=false -o mitm .
```

> For educational use only. Only run against machines you own or have explicit permission to test.
