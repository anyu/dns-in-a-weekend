package main

import "testing"

func TestDNSHeaderToBytes(t *testing.T) {
	header := DNSHeader{
		ID:            4884,
		QuestionCount: 1,
		Flags:         0,
	}

	expected := "\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
	actual := string(header.toBytes())

	if actual != expected {
		t.Errorf("Expected: %s, but got: %s", expected, actual)
	}
}
