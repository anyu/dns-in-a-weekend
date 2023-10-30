package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

type DNSRecord struct {
	Name []byte
	// Type is an unsigned 16 bit integer specifying the type of record being queried, eg. A
	Type uint16
	// Class an unsigned 16 bit integer specifying the class of records being queried. Always the same, 1 for IN.
	Class uint16
	// TTL specifies how long to cache the query for.
	TTL uint32
	// Data represents the content, like the IP.
	Data []byte
}

func parseHeader(r *bytes.Reader) (DNSHeader, error) {
	header := DNSHeader{}
	err := binary.Read(r, binary.BigEndian, &header.ID)
	if err != nil {
		return DNSHeader{}, err
	}
	err = binary.Read(r, binary.BigEndian, &header.Flags)
	if err != nil {
		return DNSHeader{}, err
	}
	err = binary.Read(r, binary.BigEndian, &header.QuestionCount)
	if err != nil {
		return DNSHeader{}, err
	}
	err = binary.Read(r, binary.BigEndian, &header.AnswerCount)
	if err != nil {
		return DNSHeader{}, err
	}
	err = binary.Read(r, binary.BigEndian, &header.AuthorityCount)
	if err != nil {
		return DNSHeader{}, err
	}
	err = binary.Read(r, binary.BigEndian, &header.AdditionalCount)
	if err != nil {
		return DNSHeader{}, err
	}
	return header, nil
}

func decodeDNSName(r io.Reader) (string, error) {
	labels := []string{}
	for {
		// Read in a single byte from the reader
		lengthByte := make([]byte, 1)
		_, err := r.Read(lengthByte)
		if err != nil {
			return "", fmt.Errorf("error decoding name, %v", err)
		}
		// DNS domain names are terminated by a 0-byte
		length := int(lengthByte[0])
		if length == 0 { // stop if domain name has terminated
			break
		}

		// Use a bitmask to mask the 2 leftmost bits of the length byte to check if they are set to 1.
		// If both are set to 1, it indicates a pointer to a compressed name in the DNS message
		// and the following bits specify the offset of the compressed name.
		if length&0b11000000 == 0b11000000 { // 0xc0 in hexadecimal
			compressedName, err := decodeCompressedName(r, length)
			if err != nil {
				return "", fmt.Errorf("error decoding compressed name %v", err)
			}
			labels = append(labels, compressedName)
			break
		} else {
			// It's a regular non-compressed label
			labelBytes := make([]byte, length)
			_, err = r.Read(labelBytes)
			if err != nil {
				return "", fmt.Errorf("error reading label, %v", err)
			}
			labels = append(labels, string(labelBytes))
		}
	}
	return strings.Join(labels, "."), nil
}

func decodeCompressedName(r io.Reader, length int) (string, error) {

	singleByte := make([]byte, 1)
	_, err := r.Read(singleByte)
	if err != nil {
		return "", fmt.Errorf("error reading pointer bytes: %w", err)
	}
	// Use bitmask to CLEAR the 2 most significant bits of the length byte, which extracts the lower 6 bits of length,
	// which is the offset bits.
	offset := byte(length & 0b00111111) // 0x3f in hexadecimal

	// Combine the offset bits with the second byte to get the pointer value
	pointerBytes := []byte{offset, singleByte[0]}
	pointer := binary.BigEndian.Uint16(pointerBytes)

	// Record current position of reader
	currentPos, _ := r.(io.Seeker).Seek(0, io.SeekCurrent)

	// Seek to the pointer position
	_, err = r.(io.Seeker).Seek(int64(pointer), io.SeekStart)
	if err != nil {
		return "", err
	}

	// Decode the DNS name at the pointer position
	name, err := decodeDNSName(r)
	if err != nil {
		return "", fmt.Errorf("error decoding dns name: %w", err)
	}
	_, err = r.(io.Seeker).Seek(currentPos, io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("error seeking through reader: %w", err)
	}
	return name, nil
}

func parseQuestion(r *bytes.Reader) (DNSQuestion, error) {
	question := DNSQuestion{}
	name, err := decodeDNSName(r)
	if err != nil {
		return DNSQuestion{}, err
	}
	err = binary.Read(r, binary.BigEndian, &question.Type)
	if err != nil {
		return DNSQuestion{}, err
	}
	err = binary.Read(r, binary.BigEndian, &question.Class)
	if err != nil {
		return DNSQuestion{}, err
	}
	question.Name = []byte(name)

	return question, nil
}

func parseRecord(r *bytes.Reader) (DNSRecord, error) {
	record := DNSRecord{}
	name, err := decodeDNSName(r)
	if err != nil {
		return DNSRecord{}, err
	}
	record.Name = []byte(name)

	remainingBytes := make([]byte, 10)
	if _, err := r.Read(remainingBytes); err != nil {
		return DNSRecord{}, err
	}

	record.Type = binary.BigEndian.Uint16(remainingBytes[0:2])
	record.Class = binary.BigEndian.Uint16(remainingBytes[2:4])
	record.TTL = binary.BigEndian.Uint32(remainingBytes[4:8])

	dataLength := binary.BigEndian.Uint16(remainingBytes[8:])
	dataBytes := make([]byte, dataLength)
	_, err = r.Read(dataBytes)
	if err != nil {
		return DNSRecord{}, err
	}
	record.Data = dataBytes

	return record, nil
}
