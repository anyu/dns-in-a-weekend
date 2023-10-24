package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

const RECORD_TYPE_A = 1

const CLASS_IN = 1               // IN = internet
const RECURSION_DESIRED = 1 << 8 // 100000000 set 9th bit from right

type DNSHeader struct {
	ID             int
	Flags          int
	NumQuestions   int
	NumAnswers     int
	NumAuthorities int
	NumAdditionals int
}

func (h *DNSHeader) toBytes() []byte {
	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data[0:2], uint16(h.ID))
	binary.BigEndian.PutUint16(data[2:4], uint16(h.Flags))
	binary.BigEndian.PutUint16(data[4:6], uint16(h.NumQuestions))
	binary.BigEndian.PutUint16(data[6:8], uint16(h.NumAnswers))
	binary.BigEndian.PutUint16(data[8:10], uint16(h.NumAuthorities))
	binary.BigEndian.PutUint16(data[10:12], uint16(h.NumAdditionals))
	return data
}

type DNSQuestion struct {
	Name  []byte // eg. example.com
	Type  int    // eg. A
	Class int
}

func (q *DNSQuestion) toBytes() []byte {
	data := make([]byte, len(q.Name)+4)
	copy(data, q.Name)

	binary.BigEndian.PutUint16(data[len(q.Name):len(q.Name)+2], uint16(q.Type))
	binary.BigEndian.PutUint16(data[len(q.Name)+2:len(q.Name)+4], uint16(q.Class))
	return data
}

func main() {

	destination := "8.8.8.8:53"
	queryBytes := buildQuery("www.example.com", RECORD_TYPE_A)

	err := sendQueryWithUDP(queryBytes, destination)
	if err != nil {
		log.Fatalf("error sending UDP query: %v\n", err)
	}
	fmt.Println("query sent")
}

func encodeDNSName(domainName string) []byte {
	encoded := []byte{}
	parts := strings.Split(domainName, ".")

	for _, part := range parts {
		partBytes := []byte(part)
		partByteLength := byte(len(partBytes))
		encoded = append(encoded, partByteLength)
		encoded = append(encoded, partBytes...)
	}
	// Terminate the DNS name with a null byte
	encoded = append(encoded, 0)
	return encoded
}

func sendQueryWithUDP(queryBytes []byte, destination string) error {
	conn, err := net.Dial("udp", destination)
	if err != nil {
		return fmt.Errorf("error creating UDP connection: %v\n", err)
	}
	defer conn.Close()

	_, err = conn.Write(queryBytes)
	if err != nil {
		return fmt.Errorf("error sending data: %v\n", err)
	}
	return nil
}

func buildQuery(domainName string, recordType int) []byte {
	name := encodeDNSName(domainName)
	rand.Seed(time.Now().UnixNano())
	min := 10
	max := 5000
	id := rand.Intn(max-min+1) + min

	header := DNSHeader{
		ID:           id,
		NumQuestions: 1,
		Flags:        RECURSION_DESIRED,
	}

	question := DNSQuestion{
		Name:  name,
		Type:  recordType,
		Class: CLASS_IN,
	}
	return append(header.toBytes(), question.toBytes()...)
}
