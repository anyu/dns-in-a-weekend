package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
)

const (
	// IN = internet
	classIN = 1
	// 100000000 set 9th bit from right
	recursionDesired = 1 << 8
)
const maxUint16Value = 2 ^ 16 - 1 // 65535
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
	// We can create a fixed-size byte slice of 12 bytes since we have six 2-byte sized fields.
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], h.ID)
	binary.BigEndian.PutUint16(b[2:4], h.Flags)
	binary.BigEndian.PutUint16(b[4:6], h.QuestionCount)
	binary.BigEndian.PutUint16(b[6:8], h.AnswerCount)
	binary.BigEndian.PutUint16(b[8:10], h.AuthorityCount)
	binary.BigEndian.PutUint16(b[10:12], h.AdditionalCount)
	return b
}

type DNSQuestion struct {
	// Name is the domain name being queried, eg. example.com
	Name []byte
	// Type is an unsigned 16 bit integer specifying the type of the record being queried, eg. A
	Type uint16
	// Class an unsigned 16 bit integer specifying the class of the record being queried. Always the same, 1 for IN.
	Class uint16
}

func (q *DNSQuestion) toBytes() []byte {
	nameSize := len(q.Name)
	b := make([]byte, nameSize+4) // plus 2 bytes for Type, 2 bytes for Class
	// copy the Name bytes to the buffer
	copy(b[0:nameSize], q.Name)

	binary.BigEndian.PutUint16((b[nameSize : nameSize+2]), q.Type)
	binary.BigEndian.PutUint16((b[nameSize+2 : nameSize+4]), q.Class)
	return b
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

func buildQuery(domainName string, recordType uint16, useRecursion bool) []byte {
	name := encodeDNSName(domainName)
	id := uint16(rand.Intn(maxUint16Value))

	flags := uint16(0)
	if useRecursion {
		flags = recursionDesired
	}

	header := DNSHeader{
		ID:            id,
		QuestionCount: 1,
		Flags:         flags,
	}

	question := DNSQuestion{
		Name:  name,
		Type:  recordType,
		Class: classIN,
	}
	buf := bytes.Buffer{}
	buf.Write(header.toBytes())
	buf.Write(question.toBytes())
	return buf.Bytes()
}

func sendQuery(queryBytes []byte, ip string) (DNSPacket, error) {
	conn, err := net.Dial("udp", ip+":"+dnsPort)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("error creating UDP connection: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(queryBytes)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("error sending data: %v", err)
	}

	resp := make([]byte, 1024)
	_, err = conn.Read(resp)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("error receiving response: %v", err)
	}
	packet, err := parseDNSPacket(resp)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("error parsing DNS packet: %v", err)
	}
	return packet, nil
}
