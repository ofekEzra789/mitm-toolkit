package main

import (
	"fmt"
	"strings"
	"time"
)

// Extract from the header: method + URL
func parseHTTP(payload string) {

	// Need to split the payload for lines
	payloadLines := strings.Split(payload, "\n")

	if len(payloadLines) == 0 {
		return
	}

	// extract the first line
	firstLine := payloadLines[0]

	// check if : request or response
	if strings.HasPrefix(firstLine, "HTTP/") {
		// This is a response
		parts := strings.Split(firstLine, " ")

		if len(parts) >= 2 {
			statusCode := parts[1]
			statusText := ""

			if len(parts) >= 3 {
				statusText = parts[2] // "The OK"
			}
			fmt.Printf("[%v] [HTTP Response] %v %v\n", time.Now().Format("15:04:05"), statusCode, statusText)
		}

	} else {
		// This is a request
		parts := strings.Split(firstLine, " ")

		if len(parts) >= 2 {

			method := parts[0]
			path := parts[1]

			host := ""

			for _, line := range payloadLines {
				if strings.HasPrefix(line, "Host:") {
					host = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
					break
				}
			}

			if host != "" {
				fmt.Printf("[%v] [HTTP Request] %v http://%v%v\n", time.Now().Format("15:04:05"), method, host, path)
			} else {
				fmt.Printf("[%v] [HTTP Request] %v %v\n", time.Now().Format("15:04:05"), method, path)
			}

		}

	}

}
