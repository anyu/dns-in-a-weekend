package main

import (
	"fmt"
	"log"
	"strings"
)

func main() {
	domain := "twitter.com"
	ip, err := resolve(domain, recordTypeA)
	if err != nil {
		log.Fatalf("error resolving domain: %v", err)
	}
	fmt.Printf("ip: %q", ip)
}

func ipToString(ip []byte) string {
	parts := make([]string, len(ip))
	for i, val := range ip {
		parts[i] = fmt.Sprintf("%d", val)
	}
	return strings.Join(parts, ".")
}
