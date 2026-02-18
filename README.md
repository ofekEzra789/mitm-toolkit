# MITM ARP Spoofing Tool

A Man-in-the-Middle tool written in Go for educational purposes. Performs ARP cache poisoning to intercept network traffic between a target and its gateway.

## How it works

1. Discovers the local network interface and gateway
2. Resolves MAC addresses via ARP requests
3. Poisons the ARP cache of both the target and the gateway
4. Enables IP forwarding so the victim stays connected
5. Restores ARP tables on exit (Ctrl+C)

## Usage

```bash
sudo ./mitm -t <target_ip>
```

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

## Build

```bash
go build -buildvcs=false -o mitm .
```

> For educational use only. Only run against machines you own or have explicit permission to test.
