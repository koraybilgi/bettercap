package network

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/bettercap/bettercap/core"
)

type ArpTable map[string]IpVersions

type IpVersions struct {
	IPv4 string
	IPv6 string
}

var (
	arpWasParsed = false
	arpLock      = &sync.RWMutex{}
	arpTable     = make(ArpTable)
)

func ArpUpdate(iface string) (ArpTable, error) {
	arpLock.Lock()
	defer arpLock.Unlock()

	// Signal we parsed the ARP table at least once.
	arpWasParsed = true

	// Run "arp -an" (darwin) or "ip neigh" (linux) and parse the output
	output, err := core.Exec(ArpCmd, ArpCmdOpts)
	if err != nil {
		return arpTable, err
	}

	newTable := make(ArpTable)
	for _, line := range strings.Split(output, "\n") {
		m := ArpTableParser.FindStringSubmatch(line)
		if len(m) == ArpTableTokens {
			ipIndex := ArpTableTokenIndex[0]
			hwIndex := ArpTableTokenIndex[1]
			ifIndex := ArpTableTokenIndex[2]

			if m[hwIndex] == "0a:40:fe:d5:8b:6d" {
				//log.Warning("ArpUpdate IP: %v MAC: %v IFACE1: %v IFACE2: %v", m[ipIndex], m[hwIndex], m[ifIndex], iface)
			}
			ifname := iface

			if ifIndex != -1 {
				ifname = m[ifIndex]
			}

			if ifname != iface {
				continue
			}

			address := net.ParseIP(m[ipIndex])
			if address != nil {
				mac := m[hwIndex]

				if _, exists := newTable[mac]; !exists {
					newTable[mac] = IpVersions{}
				}

				ipList := newTable[mac]
				
				if address.To4() != nil {
					ipList.IPv4 = address.String()
				} else {
					ipList.IPv6 = address.String()
				}
				newTable[mac] = ipList

				//mod.Warning("IPv4: %s - IPv6: %s - CMAC: %s HMAC: %s - Found: %s", endpoint_ipv4, endpoint_ipv6, client_mac, e.HwAddress, found)
			}
		}
	}

	arpTable = newTable

	return arpTable, nil
}

func ArpLookup(iface string, address string, refresh bool) (string, error) {
	// Refresh ARP table if first run or if a force refresh has been instructed.
	if !ArpParsed() || refresh {
		if _, err := ArpUpdate(iface); err != nil {
			return "", err
		}
	}

	arpLock.RLock()
	defer arpLock.RUnlock()

	// Lookup the hardware address of this IP.
	for mac, ipList := range arpTable {
		if ipList.IPv4 == address || ipList.IPv6 == address {
			return mac, nil
		}
	}

	return "", fmt.Errorf("Could not find MAC for %s", address)
}

func ArpInverseLookup(iface string, mac string, refresh bool) (*IpVersions, error) {
	if !ArpParsed() || refresh {
		if _, err := ArpUpdate(iface); err != nil {
			return nil, err
		}
	}

	arpLock.RLock()
	defer arpLock.RUnlock()

	for hw, ipVersions := range arpTable {
		if hw == mac {
			if ipVersions.IPv4 != "" {
				return &ipVersions, nil
			}
			if ipVersions.IPv6 != "" {
				return &ipVersions, nil
			}
		}
	}

	return nil, fmt.Errorf("Could not find IP for %s", mac)
}

func ArpParsed() bool {
	arpLock.RLock()
	defer arpLock.RUnlock()
	return arpWasParsed
}
