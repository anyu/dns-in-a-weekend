package main

import (
	"fmt"
	"log"
	"os"

	"dns-in-a-weekend/dns"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Provide a domain name")
		return
	}
	domain := os.Args[1]

	ip, err := dns.Resolve(domain)
	if err != nil {
		log.Fatalf("error resolving domain: %v", err)
	}
	fmt.Printf("ip: %q", ip)
}
