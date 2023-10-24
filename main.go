package main

import (
	"bytes"
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
const MAX_UINT_16_VAL = 65535

type DNSHeader struct {
	// ID is a 16 bit identifier for a query. A new random ID should be used for each request.
	ID uint16
	// Flags specifies the requested operation and a response code.
	Flags uint16
	// QuestionCount is an unsigned 16 bit integer specifying the # of entries in the question section (aka. `QDCOUNT`)
	QuestionCount uint16
	// AnswerCount is an unsigned 16 bit integer specifying the # of resource records in the answer section (aka. `ANCOUNT`)
	AnswerCount uint16
	// AuthorityCount is an unsigned 16 bit integer specifying the # of name server resource records in the authority records section (aka. `NSCOUNT`)
	AuthorityCount uint16
	// AdditionalCount is an unsigned 16 bit integer specifying the # of resource records in the additional records section. (aka. `ARCOUNT`)
	AdditionalCount uint16
}

func (h *DNSHeader) toBytes() []byte {
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, h.ID)
	binary.Write(&buf, binary.BigEndian, h.Flags)
	binary.Write(&buf, binary.BigEndian, h.QuestionCount)
	binary.Write(&buf, binary.BigEndian, h.AnswerCount)
	binary.Write(&buf, binary.BigEndian, h.AuthorityCount)
	binary.Write(&buf, binary.BigEndian, h.AdditionalCount)
	return buf.Bytes()
}

type DNSQuestion struct {
	// Name is the domain name being queried, eg. example.com
	Name []byte
	// Type is the type of record being queried, eg. A
	Type uint16
	// Class is the class of records being queried
	Class uint16
}

func (q *DNSQuestion) toBytes() []byte {
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, q.Name)
	binary.Write(&buf, binary.BigEndian, q.Type)
	binary.Write(&buf, binary.BigEndian, q.Class)
	return buf.Bytes()
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

// DNS expects each label (e.g., "www" or "example") to be preceded
// by a one-byte length field specifying the label's length.
func encodeDNSName(domainName string) []byte {
	buf := bytes.Buffer{}
	// Splits `www.example.com` to `www`, `example, `com` (also called labels)
	labels := strings.Split(domainName, ".")

	for _, label := range labels {
		labelByteLength := byte(len(label))
		buf.WriteByte(labelByteLength)
		buf.WriteString(label)
	}
	// Terminate name with a null byte (signals no more labels)
	buf.WriteByte(0)
	return buf.Bytes()
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

func buildQuery(domainName string, recordType uint16) []byte {
	name := encodeDNSName(domainName)
	rand.Seed(time.Now().UnixNano())
	id := uint16(rand.Intn(MAX_UINT_16_VAL))

	header := DNSHeader{
		ID:            id,
		QuestionCount: 1,
		Flags:         RECURSION_DESIRED,
	}

	question := DNSQuestion{
		Name:  name,
		Type:  recordType,
		Class: CLASS_IN,
	}
	buf := bytes.Buffer{}
	buf.Write(header.toBytes())
	buf.Write(question.toBytes())
	return buf.Bytes()
}
