package main

import (
	"bytes"
	"fmt"
	"log"
)

func main() {
	domain := "www.example.com"
	nameserverIP := "8.8.8.8"

	resp, err := sendQuery(domain, nameserverIP)
	if err != nil {
		log.Fatalf("error sending UDP query: %v\n", err)
	}
	reader := bytes.NewReader(resp)
	header, err := parseHeader(reader)
	if err != nil {
		log.Fatalf("error parsing DNS header: %v\n", err)
	}
	question, err := parseQuestion(reader)
	if err != nil {
		log.Fatalf("error parsing DNS question: %v\n", err)
	}
	record, err := parseRecord(reader)
	if err != nil {
		log.Fatalf("error parsing DNS record: %v\n", err)
	}
	fmt.Printf("header: %v", header)
	fmt.Printf("question name: %s", question.Name)
	fmt.Printf("record: %s", record.Name)
	// fmt.Printf("record type: %v", record.Type)
	// fmt.Printf("record data: %s", record.Data)
}
