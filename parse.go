package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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
			fmt.Errorf("error decoding name, %w", err)
			break
		}
		// DNS domain names are terminated by a 0-byte, so
		// check if the first element of the returned byte is 0.
		length := int(lengthByte[0])
		if length == 0 {
			break
		}

		// Use bitmask to mask the 2 most significant bits of the length byte and check if they are set to 1.
		// If both of are set to 1, the length byte is a pointer to a compressed name in the DNS message
		// and the following bits specify the offset of the compressed name.
		if (length & 0xc0) == 0xc0 { // 11000000 in binary
			offsetByte := make([]byte, 1)
			_, err := r.Read(offsetByte)
			if err != nil {
				fmt.Errorf("error reading compressed name offset, %w", err)
				break
			}

			// Use bitmask to CLEAR the 2 most significant bits of the length byte, which extracts the lower 6 bits of length,
			// which represent a part of the offset. 0x3f = 00111111 in binary.
			lowerLengthBits := length & 0x3f

			// Retrieves the first byte of the offsetByte as an integer. Represents the lower 8 bits of the offset.
			offsetByteFirstByteAsInt := int(offsetByte[0])
			// Move the lower 6 bits to the higher 6 bits position in a 16-bit integer.
			// The 2 most significant bits are zeroed in the process.
			// Result is a 16-bit value where bits 0-7 = 0, bits 8-13 = the lower 6 bits of `length`.

			lowerLengthBitsShifted := lowerLengthBits << 8
			// Use  bitwise OR to combine the 2 16-bit values obtained above.
			// Result is a 16-bit integer where the lower 8 bits are set to the value in offsetByte,
			// and the higher 6 bits are set to the lower 6 bits of length.
			offset := int(lowerLengthBitsShifted | offsetByteFirstByteAsInt)

			compressedName, err := decodeCompressedName(r, offset)
			if err != nil {
				fmt.Errorf("error decoding name, %w", err)
				break
			}
			labels = append(labels, compressedName)
			break
		} else {
			labelBytes := make([]byte, length)
			_, err := r.Read(labelBytes)
			if err != nil {
				fmt.Errorf("error  name, %w", err)
				break
			}
			labels = append(labels, string(labelBytes))
		}
	}
	b := bytes.Join(labels, []byte("."))
	return b, nil
}

func decodeCompressedName(reader io.Reader, offset int) (string, error) {
	offsetReader := io.LimitReader(reader, int64(offset))
	name, err := decodeDNSName(offsetReader)
	if err != nil {
		return "", fmt.Errorf("error decoding dns name: %w", err)
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
