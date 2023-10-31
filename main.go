package main

import (
	"fmt"
	"log"
	"strings"
)

func main() {
	domain := "www.example.com"
	nameserverIP := "8.8.8.8"
	ip, err := lookupDomain(domain, nameserverIP, false)
	if err != nil {
		log.Fatalf("error looking up domain: %v", err)
	}
	fmt.Println(ip)
}

func ipToString(ip []byte) string {
	parts := make([]string, len(ip))
	for i, val := range ip {
		parts[i] = fmt.Sprintf("%d", val)
	}
	return strings.Join(parts, ".")
}

func lookupDomain(domain, nameserverIP string, useRecursion bool) (string, error) {
	queryBytes := buildQuery(domain, recordTypeA, useRecursion)
	packet, err := sendQuery2(queryBytes, nameserverIP)
	if err != nil {
		return "", fmt.Errorf("error sending UDP query: %v", err)
	}
	// packet, err := parseDNSPacket(resp)
	// if err != nil {
	// 	return "", fmt.Errorf("error parsing DNS packet: %v", err)
	// }
	ip := ipToString(packet.Answers[0].Data)
	return ip, nil
}
