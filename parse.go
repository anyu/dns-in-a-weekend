package main

import (
	"bytes"
	"encoding/binary"
)

type DNSRecord struct {
	Name []byte
	// Type is the type of record being queried, eg. A
	Type int
	// Class is the class of records being queried. Always the same, 1 for IN.
	Class int
	// TTL specifies long to cache the query for.
	TTL int
	// Data represents the content, like the IP.
	Data []byte
}

func parseHeader(r *bytes.Reader) DNSRecord {
	record := DNSRecord{}
	binary.Read(r, binary.BigEndian, &record.Type)
	binary.Read(r, binary.BigEndian, &record.Class)
	binary.Read(r, binary.BigEndian, &record.TTL)
	return record
}
