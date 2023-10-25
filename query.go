package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	recordTypeA = 1
	// IN = internet
	classIN = 1
	// 100000000 set 9th bit from right
	recursionDesired = 1 << 8
)
const maxUint16Value = 65535
const dnsPort = "53"

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
	// Class is the class of records being queried. Always the same, 1 for IN.
	Class uint16
}

func (q *DNSQuestion) toBytes() []byte {
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, q.Name)
	binary.Write(&buf, binary.BigEndian, q.Type)
	binary.Write(&buf, binary.BigEndian, q.Class)
	return buf.Bytes()
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

func buildQuery(domainName string, recordType uint16) []byte {
	name := encodeDNSName(domainName)
	// id := uint16(rand.Intn(maxUint16Value))

	// header := DNSHeader{
	// 	ID:            id,
	// 	QuestionCount: 1,
	// 	Flags:         recursionDesired,
	// }
	header := DNSHeader{
		ID:            4884,
		QuestionCount: 1,
		Flags:         0,
	}
	// header_to_bytes(DNSHeader(id=, flags=0, num_questions=1, num_additionals=0, num_authorities=0, num_answers=0))

	question := DNSQuestion{
		Name:  name,
		Type:  recordType,
		Class: classIN,
	}
	buf := bytes.Buffer{}
	h := header.toBytes()
	fmt.Printf("q: %q\n", h)
	fmt.Printf("p: %p\n", h)
	fmt.Printf("#x: %#x\n", h)
	q := question.toBytes()
	fmt.Printf("x: %x\n", q)

	buf.Write(header.toBytes())
	buf.Write(question.toBytes())
	return buf.Bytes()
}

func sendQuery(domainName, ip string) (*bytes.Reader, error) {
	queryBytes := buildQuery(domainName, recordTypeA)

	conn, err := net.Dial("udp", ip+":"+dnsPort)
	if err != nil {
		return nil, fmt.Errorf("error creating UDP connection: %v\n", err)
	}
	defer conn.Close()

	_, err = conn.Write(queryBytes)
	if err != nil {
		return nil, fmt.Errorf("error sending data: %v\n", err)
	}

	resp := make([]byte, 1024)
	_, err = conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("error receiving response: %v\n", err)
	}

	return bytes.NewReader(resp), nil
}
