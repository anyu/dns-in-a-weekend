package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
	// "log"
	// "math/rand"
	// "net"
	// "strings"
	// "time"
)

const RECORD_TYPE_A = 1

// IN = internet
const CLASS_IN = 1
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
	// hexString := "3c5f0100000100000000000003777777076578616d706c6503636f6d0000010001"

	// queryBytes, err := hex.DecodeString(hexString)
	// if err != nil {
	// 	log.Fatalf("error decoding hex string: %v\n", err)
	// }

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
	// min := 10
	// max := 5000
	// id := rand.Intn(max-min+1) + min
	id := 0x8298

	header := DNSHeader{
		ID:           id,
		NumQuestions: 1,
		Flags:        0,
	}

	question := DNSQuestion{
		Name:  name,
		Type:  recordType,
		Class: CLASS_IN,
	}
	return append(header.toBytes(), question.toBytes()...)
}

// dnsH := DNSHeader{
// 	ID:             0x1314,
// 	Flags:          0,
// 	NumQuestions:   1,
// 	NumAnswers:     0,
// 	NumAuthorities: 0,
// 	NumAdditionals: 0,
// }

// b, err := headerToBytes(dnsH)
// if err != nil {
// 	log.Fatalf("error converting header to bytes: %v", err)
// }
// hexLiteral := bytesToHexLiteral(b)

// fmt.Println(hexLiteral)
// func bytesToHexLiteral(bytes []byte) string {
// 	result := "b'"
// 	for _, b := range bytes {
// 		result += fmt.Sprintf("\\x%02x", b)
// 	}
// 	result += "'"
// 	return result
// }

// header := DNSHeader{
// 	ID:             0x1314,
// 	Flags:          0,
// 	NumQuestions:   1,
// 	NumAnswers:     0,
// 	NumAuthorities: 0,
// 	NumAdditionals: 0,
// }
// headerBytes := header.toBytes()
// fmt.Printf("%x", headerBytes)

// domainName := "google.com"
// encodedDNSName := encodeDNSName(domainName)
// fmt.Printf("%x\n", encodedDNSName)
