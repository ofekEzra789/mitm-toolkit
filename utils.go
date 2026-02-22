package main

import (
	"strings"
	"time"

	"github.com/fatih/color"
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
			color.Yellow("%-10s  %-16s %s %s\n", time.Now().Format("15:04:05"), "HTTP Response", statusCode, statusText)
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
				color.Green("%-10s  %-16s %s http://%v%v\n", time.Now().Format("15:04:05"), "HTTP Request", method, host, path)
			} else {
				color.Green("%-10s  %-16s %s %s\n", time.Now().Format("15:04:05"), "HTTP Request", method, path)
			}

			if method == "POST" || method == "PUT" || method == "PATCH" {
				if idx := strings.Index(payload, "\r\n\r\n"); idx != -1 {
					body := strings.TrimSpace(payload[idx+4:])
					if body != "" {
						color.Magenta("%-10s  %-16s %s\n", time.Now().Format("15:04:05"), "POST Body", body)
					}
				}
			}

		}

	}

}
