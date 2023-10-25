package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeader(t *testing.T) {
	header := DNSHeader{
		ID:            4884,
		QuestionCount: 1,
		Flags:         0,
	}
	expected := "\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
	actual := string(header.toBytes())
	assert.Equal(t, expected, actual)
}
