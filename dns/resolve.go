package dns

import (
	"errors"
	"fmt"
)

const (
	// A = address record
	recordTypeA = 1
	// NS = nameserver record
	recordTypeNS = 2
)

func Resolve(domainName string) (string, error) {
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

		if ip := dnsPacket.getAnswer(); ip != nil {
			return string(ip), nil
		} else if nsIP := dnsPacket.getNameserverIP(); nsIP != nil {
			nameserver = string(nsIP)
		} else if nsDomain := dnsPacket.getNameserver(); nsDomain != "" {
			// resolve ns domain to IP if IP not found
			nameserver, err = Resolve(nsDomain)
			if err != nil {
				return "", fmt.Errorf("error resolving: %v", err)
			}
		} else {
			return "", errors.New("unknown error occurred")
		}
	}
}
