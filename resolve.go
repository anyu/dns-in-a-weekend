package main

import (
	"errors"
	"fmt"
)

func getAnswer(p DNSPacket) []byte {
	// return the first A record in the Answer section
	for _, a := range p.Answers {
		if a.Type == recordTypeA {
			return a.Data
		}
	}
	return nil
}

func getNameserverIP(p DNSPacket) []byte {
	// return the first A record in the Additional section
	for _, a := range p.Additionals {
		if a.Type == recordTypeA {
			return a.Data
		}
	}
	return nil
}

func getNameserver(p DNSPacket) string {
	// return the first NS record in the Authority section
	for _, a := range p.Authorities {
		if a.Type == recordTypeNS {
			return string(a.Data)
		}
	}
	return ""
}

func resolve(domainName string, recordType int) (string, error) {
	// IP of root server `a.root-servers.net`
	// https://www.iana.org/domains/root/servers
	nameserver := "198.41.0.4"

	for {
		fmt.Printf("Querying %s for %s...\n", nameserver, domainName)

		queryBytes := buildQuery(domainName, recordTypeA, false)
		dnsPacket, err := sendQuery(queryBytes, nameserver)
		if err != nil {
			return "", fmt.Errorf("error sending query: %v", err)
		}

		if ip := getAnswer(dnsPacket); ip != nil {
			return string(ip), nil
		} else if nsIP := getNameserverIP(dnsPacket); nsIP != nil {
			nameserver = string(nsIP)
		} else if nsDomain := getNameserver(dnsPacket); nsDomain != "" {
			// resolve ns domain to IP if IP not found
			nameserver, err = resolve(nsDomain, recordTypeA)
			if err != nil {
				return "", fmt.Errorf("error resolving: %v", err)
			}
		} else {
			return "", errors.New("unknown error occurred")
		}
	}
}
