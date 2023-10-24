package main

import (
	"fmt"
	"log"
)

func main() {
	domain := "www.example.com"
	nameserverIP := "8.8.8.8"

	respReader, err := sendQuery(domain, nameserverIP)
	if err != nil {
		log.Fatalf("error sending UDP query: %v\n", err)
	}
	record := parseHeader(respReader)
	fmt.Printf("response: %v", record)
}
