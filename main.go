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
	header, err := parseHeader(respReader)
	if err != nil {
		log.Fatalf("error parsing DNS header: %v\n", err)
	}
	question, err := parseQuestion(respReader)
	if err != nil {
		log.Fatalf("error parsing DNS question: %v\n", err)
	}
	fmt.Printf("header: %v", header)
	fmt.Printf("question domain name: %s", question.Name)
}
