package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

type Record struct {
	// Name is the domain name to which the record applies.
	Name []byte
	// Type is an unsigned 16 bit integer specifying the type of the record, eg. A
	Type uint16
	// Class an unsigned 16 bit integer specifying the class of the record. Always the same, 1 for IN.
	Class uint16
	// TTL specifies how long to cache the query for.
	TTL uint32
	// Data represents the content, like the IP.
	Data []byte
}

type Packet struct {
	// Header contains the DNS header information for the packet.
	Header Header
	// Questions holds DNS questions included in the packet.
	Questions []Question
	// Answers holds DNS records that provide answers to the questions in the packet.
	Answers []Record
	// Authorities holds DNS records that specify the uthoritative servers for the queried domain.
	Authorities []Record
	// Additionals holds additional DNS records that may include extra information relevant to the DNS query.
	Additionals []Record
}

func (p Packet) getAnswer() []byte {
	// return the first A record in the Answer section
	for _, a := range p.Answers {
		if a.Type == recordTypeA {
			return a.Data
		}
	}
	return nil
}

func (p Packet) getNameserverIP() []byte {
	// return the first A record in the Additional section
	for _, a := range p.Additionals {
		if a.Type == recordTypeA {
			return a.Data
		}
	}
	return nil
}

func (p Packet) getNameserver() string {
	// return the first NS record in the Authority section
	for _, a := range p.Authorities {
		if a.Type == recordTypeNS {
			return string(a.Data)
		}
	}
	return ""
}

func parsePacket(data []byte) (Packet, error) {
	r := bytes.NewReader(data)
	header, err := parseHeader(r)
	if err != nil {
		return Packet{}, fmt.Errorf("error parsing DNS header: %v", err)
	}

	questions := []Question{}
	qCount := int(header.QuestionCount)
	for i := 0; i < qCount; i++ {
		q, err := parseQuestion(r)
		if err != nil {
			return Packet{}, fmt.Errorf("error parsing DNS question: %v", err)
		}
		questions = append(questions, q)
	}

	answers := []Record{}
	ansCount := int(header.AnswerCount)
	for i := 0; i < ansCount; i++ {
		answer, err := parseRecord(r)
		if err != nil {
			return Packet{}, fmt.Errorf("error parsing DNS record: %v", err)
		}
		answers = append(answers, answer)
	}

	authorities := []Record{}
	authCount := int(header.AuthorityCount)
	for i := 0; i < authCount; i++ {
		authority, err := parseRecord(r)
		if err != nil {
			return Packet{}, fmt.Errorf("error parsing DNS record: %v", err)
		}
		authorities = append(authorities, authority)
	}

	additionals := []Record{}
	additionalCount := int(header.AdditionalCount)
	for i := 0; i < additionalCount; i++ {
		additional, err := parseRecord(r)
		if err != nil {
			return Packet{}, fmt.Errorf("error parsing DNS record: %v", err)
		}
		additionals = append(additionals, additional)
	}
	return Packet{
		Header:      header,
		Questions:   questions,
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
	}, nil

}

func parseHeader(r *bytes.Reader) (Header, error) {
	header := Header{}
	err := binary.Read(r, binary.BigEndian, &header.ID)
	if err != nil {
		return Header{}, err
	}
	err = binary.Read(r, binary.BigEndian, &header.Flags)
	if err != nil {
		return Header{}, err
	}
	err = binary.Read(r, binary.BigEndian, &header.QuestionCount)
	if err != nil {
		return Header{}, err
	}
	err = binary.Read(r, binary.BigEndian, &header.AnswerCount)
	if err != nil {
		return Header{}, err
	}
	err = binary.Read(r, binary.BigEndian, &header.AuthorityCount)
	if err != nil {
		return Header{}, err
	}
	err = binary.Read(r, binary.BigEndian, &header.AdditionalCount)
	if err != nil {
		return Header{}, err
	}
	return header, nil
}

func parseQuestion(r *bytes.Reader) (Question, error) {
	question := Question{}
	name, err := decodeDNSName(r)
	if err != nil {
		return Question{}, err
	}
	err = binary.Read(r, binary.BigEndian, &question.Type)
	if err != nil {
		return Question{}, err
	}
	err = binary.Read(r, binary.BigEndian, &question.Class)
	if err != nil {
		return Question{}, err
	}
	question.Name = []byte(name)

	return question, nil
}

func decodeDNSName(r io.Reader) (string, error) {
	labels := []string{}
	for {
		// Read in a single byte from the reader
		lengthByte := make([]byte, 1)
		_, err := r.Read(lengthByte)
		if err != nil {
			return "", fmt.Errorf("error reading length byte, %v", err)
		}
		// DNS domain names are terminated by a 0-byte
		length := int(lengthByte[0])
		if length == 0 { // stop if domain name has terminated
			break
		}

		// Use a bitmask to mask the 2 leftmost bits of the length byte to check if they are set to 1.
		// If both are set to 1, it indicates a pointer to a compressed name in the DNS message.
		// This length byte and the byte immediately after form a "compression pointer".
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
	// Use bitmask to clear the 2 most significant bits of the length byte, leaving the lower 6 bits left which stores the offset bits.
	// The offset is the offset from the start of the DNS message to the location of the actual domain name.
	offset := byte(length & 0b00111111) // 0x3f in hexadecimal

	// The next byte immediately following makes up the rest of the compression pointer.
	nextByte := make([]byte, 1)
	_, err := r.Read(nextByte)
	if err != nil {
		return "", fmt.Errorf("error reading next byte that makes up compression pointer: %w", err)
	}
	// Combine the offset bits with the next byte []to create the pointer (which is an 16-bit unsigned integer)
	pointerBytes := append([]byte{offset}, nextByte...)
	pointer := binary.BigEndian.Uint16(pointerBytes)

	// Record the current position of the reader
	currentPos, err := r.(io.Seeker).Seek(0, io.SeekCurrent) // 0 = offset
	if err != nil {
		return "", fmt.Errorf("error recording current reader position: %v", err)
	}

	// Move the read position to the pointer position
	_, err = r.(io.Seeker).Seek(int64(pointer), io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("error moving reader to pointer position: %v", err)
	}

	// Decode the DNS name at the pointer position
	name, err := decodeDNSName(r)
	if err != nil {
		return "", fmt.Errorf("error decoding dns name at pointer position: %v", err)
	}
	// Move the read position back to where we left off reading the DNS message
	// since that'll be where the remainder of the DNS record fields are.
	_, err = r.(io.Seeker).Seek(currentPos, io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("error moving reader to: %v", err)
	}
	return name, nil
}

func parseRecord(r *bytes.Reader) (Record, error) {
	record := Record{}
	name, err := decodeDNSName(r)
	if err != nil {
		return Record{}, fmt.Errorf("error decoding DNS name: %v", err)
	}
	record.Name = []byte(name)

	remainingBytes := make([]byte, 10)
	if _, err := r.Read(remainingBytes); err != nil {
		return Record{}, fmt.Errorf("error reading remaining bytes: %v", err)
	}

	record.Type = binary.BigEndian.Uint16(remainingBytes[0:2])
	record.Class = binary.BigEndian.Uint16(remainingBytes[2:4])
	record.TTL = binary.BigEndian.Uint32(remainingBytes[4:8])
	dataLength := binary.BigEndian.Uint16(remainingBytes[8:])
	dataBytes := make([]byte, dataLength)

	if record.Type == recordTypeNS {
		data, err := decodeDNSName(r)
		if err != nil {
			return Record{}, fmt.Errorf("error decoding name: %v", err)
		}
		record.Data = []byte(data)
	} else if record.Type == recordTypeA {
		_, err := r.Read(dataBytes)
		if err != nil {
			return Record{}, fmt.Errorf("error reading data bytes: %v", err)
		}
		record.Data = []byte(ipToString(dataBytes))
	} else {
		_, err := r.Read(dataBytes)
		if err != nil {
			return Record{}, fmt.Errorf("error reading data bytes: %v", err)
		}
		record.Data = dataBytes
	}

	return record, nil
}

func ipToString(ip []byte) string {
	parts := make([]string, len(ip))
	for i, val := range ip {
		parts[i] = fmt.Sprintf("%d", val)
	}
	return strings.Join(parts, ".")
}
