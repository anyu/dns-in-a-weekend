package main

import (
	"fmt"
	"log"
	"strings"
)

func main() {
	domain := "www.example.com"
	nameserverIP := "8.8.8.8"

	resp, err := sendQuery(domain, nameserverIP)
	if err != nil {
		log.Fatalf("error sending UDP query: %v\n", err)
	}
	packet, err := parseDNSPacket(resp)
	if err != nil {
		log.Fatalf("error parsing DNS packet: %v", err)
	}
	ip := ipToString(packet.Answers[0].Data)
	fmt.Println(ip)
}

func ipToString(ip []byte) string {
	parts := make([]string, len(ip))
	for i, val := range ip {
		parts[i] = fmt.Sprintf("%d", val)
	}
	return strings.Join(parts, ".")
}
