# Lab Setup - DHCPv6 / MITM6

> This lab is specifically for the DHCPv6 rogue server and MITM6 attack modes.
> For ARP spoofing and DHCP attacks, only VM1 and a target machine are needed.

## Requirements

| VM | Role | Install |
|----|------|---------|
| VM1 - Kali | Attacker | `sudo apt install libpcap-dev golang` |
| VM2 - Ubuntu Server | Router | `sudo apt install radvd` |
| VM3 - Ubuntu Server | DHCPv6 Server | `sudo apt install dnsmasq` |
| VM4 - Ubuntu Desktop | Victim | `sudo apt install isc-dhcp-client` |

## Config Files

| VM | File | Place at |
|----|------|----------|
| VM1 | `vm1-attacker/interfaces` | run manually in terminal |
| VM2 | `vm2-router/netplan.yaml` | `/etc/netplan/50-cloud-init.yaml` |
| VM2 | `vm2-router/radvd.conf` | `/etc/radvd.conf` |
| VM2 | `vm2-router/sysctl.conf` | append to `/etc/sysctl.conf` |
| VM3 | `vm3-dhcpv6-server/netplan.yaml` | `/etc/netplan/50-cloud-init.yaml` |
| VM3 | `vm3-dhcpv6-server/dnsmasq.conf` | `/etc/dnsmasq.conf` |
| VM4 | `vm4-victim/netplan.yaml` | `/etc/netplan/50-cloud-init.yaml` |
| VM4 | `vm4-victim/NetworkManager.conf` | `/etc/NetworkManager/NetworkManager.conf` |
| VM4 | `vm4-victim/dhclient6.conf` | `/etc/dhcp/dhclient6.conf` |

## Apply Changes

**VM1:**
```bash
sudo ip -6 addr add 2001:db8::10/64 dev eth0
go build -buildvcs=false -o mitm .
```

**VM2:**
```bash
sudo netplan apply
sudo systemctl restart radvd
sudo sysctl -p /etc/sysctl.conf
```

**VM3:**
```bash
sudo netplan apply
sudo systemctl restart dnsmasq
```

**VM4:**
```bash
sudo netplan apply
sudo systemctl restart NetworkManager
# For a clean DHCPv6 start (remove cached lease):
sudo rm -f /var/lib/dhcp/dhclient6.leases
```
