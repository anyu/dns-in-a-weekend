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
	record, err := parseRecord(respReader)
	if err != nil {
		log.Fatalf("error parsing DNS record: %v\n", err)
	}
	fmt.Printf("header: %v", header)
	fmt.Printf("question name: %s", question.Name)
	fmt.Printf("record: %s", record.Name)
	fmt.Printf("record data: %s", record.Data)
}
