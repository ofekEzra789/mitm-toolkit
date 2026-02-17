package main
import (
	"fmt"
	"flag"
	"os"
)

func main() {
	// Capturing the ip address from the command line
	var target_ip_address_flag string

	flag.StringVar(&target_ip_address_flag ,"t", "", "target ip address (required)")
	flag.Parse()

	// validate that ip address was provided
	if target_ip_address_flag == "" {
		fmt.Println("Error: target IP address is required")
		fmt.Println("Usage: -t <target_ip_address>")
		os.Exit(1)
	}

	fmt.Printf("Target IP address: %v\n", target_ip_address_flag)

	// Get local network information
	localNetwork, err := GetLocalNetworkInfo()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nLocal Network Information:\n")
	fmt.Printf("  Interface: %s\n", localNetwork.interfaceName)
	fmt.Printf("  IP Address: %s\n", localNetwork.ipv4Address)
	fmt.Printf("  MAC Address: %s\n", localNetwork.macAddress)

	// Get gateway information
	gatewayIP, err := GetNetworkGateway()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nGateway Information:\n")
	fmt.Printf("  Gateway IP: %s\n", gatewayIP)

	// Get target MAC address via ARP
	targetMAC, err := GetMACFromIP(target_ip_address_flag, localNetwork)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nTarget MAC Address: %s\n", targetMAC)

	// Get gateway MAC address via ARP
	gatewayMAC, err := GetMACFromIP(gatewayIP, localNetwork)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Gateway MAC Address: %s\n", gatewayMAC)
}