package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"strings"
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
			return "", fmt.Errorf("error decoding name, %v", err)
		}
		// DNS domain names are terminated by a 0-byte, so
		// check if the first element of the returned byte is 0.
		// If it's not 0, use bitmask to mask the 2 most significant bits of the length byte and check if they are set to 1.
		// If both are set to 1, the length byte is a pointer to a compressed name in the DNS message
		// and the following bits specify the offset of the compressed name.
		length := int(lengthByte[0])
		if length == 0 {
			fmt.Printf("length is 0\n")
			break
		}
		fmt.Printf("lengthbyte: %v\n", lengthByte)
		fmt.Printf("length: %v\n", length)

		if length&0b11000000 == 0b11000000 { // 0xc0 in hexadecimal
			fmt.Print("bitmask is true\n")
			compressedName, err := decodeCompressedName(r, length)
			if err != nil {
				return "", fmt.Errorf("error decoding compressed name %v", err)
			}
			labels = append(labels, compressedName)
			break
		} else {
			// It's a regular label
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

	// Use bitmask to CLEAR the 2 most significant bits of the length byte, which extracts the lower 6 bits of length,
	// which represent a part of the offset. 0x3f in hexadecimal
	if length == 0 {
		return "", nil // The domain name is terminated
	}

	// Store the lower six bits into the first byte
	singleByte := make([]byte, 1)
	_, err := r.Read(singleByte)
	if err != nil {
		return "", fmt.Errorf("error reading pointer bytes: %w", err)
	}
	byteSlice := []byte{byte(length & 0b00111111)}
	byteSlice = append(byteSlice, singleByte...)

	fmt.Printf("byteslice: %v", byteSlice)
	// Converts byteSlice into a 16-bit unsigned int
	pointer := binary.BigEndian.Uint16(byteSlice)
	// Records current position of reader
	fmt.Printf("pointer: %v", pointer)
	currentPos, _ := r.(io.Seeker).Seek(0, io.SeekCurrent)
	fmt.Printf("currentPos: %v", currentPos)
	if pointer == 0 {
		return "", nil
	}
	// Seek until pointer position
	_, err = r.(io.Seeker).Seek(int64(pointer), io.SeekStart)
	if err != nil {
		return "", err
	}

	fmt.Printf("r: %v", r)
	name, err := decodeDNSName(r)
	if err != nil {
		return "", fmt.Errorf("error decoding dns name: %w", err)
	}
	_, err = r.(io.Seeker).Seek(currentPos, io.SeekStart)
	if err != nil {
		return "", err
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

	outputBytes := make([]byte, 10)
	_, err = r.Read(outputBytes)
	if err != nil {
		log.Printf("error decoding name, %v", err)
	}
	// err = binary.Read(r, binary.BigEndian, &record.Type)
	// if err != nil {
	// 	return DNSRecord{}, err
	// }
	// err = binary.Read(r, binary.BigEndian, &record.Class)
	// if err != nil {
	// 	return DNSRecord{}, err
	// }
	// err = binary.Read(r, binary.BigEndian, &record.TTL)
	// if err != nil {
	// 	return DNSRecord{}, err
	// }
	// err = binary.Read(r, binary.BigEndian, &record.Data)
	// if err != nil {
	// 	return DNSRecord{}, err
	// }

	return record, nil
}
