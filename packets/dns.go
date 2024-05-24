package packets

import (
	"fmt"
	"net"
	"reflect"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const DNS_UNKNOWN_QUESTION_TYPE = "Unknown"

// domain	dominio da spoofare
// d_ip		IP da assegnare al dominio
// src		IP da assegnare come sorgente
// dst		IP da ssegnare come destinazione
func NewDNSReplyFromRequest(pkt gopacket.Packet, domain string, d_ip net.IP, TTL uint32) (error, []byte) {
	/*
		Cerca un pacchetto dns che contenga solo una query di richiesta, risponde con una reply dns
		contenente la query iniziale e la risposta.
		La query deve essere di tipo A o AAAA (da implementare altri metodi)
	*/

	var err error
	var ret []byte
	var orig_src, orig_dst net.IP

	var eType layers.EthernetType
	var flag_ipv6 bool

	answers := make([]layers.DNSResourceRecord, 0)

	// Parse original packets
	orig_eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	var orig_ip4 *layers.IPv4
	var orig_ip6 *layers.IPv6
	orig_udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	orig_dns := pkt.Layer(layers.LayerTypeDNS).(*layers.DNS)

	if orig_eth == nil || orig_udp == nil || orig_dns == nil {
		return fmt.Errorf("invalid packet recived"), nil
	}

	if pkt.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		orig_ip4 = pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		orig_src = orig_ip4.SrcIP
		orig_dst = orig_ip4.DstIP
		flag_ipv6 = false
	} else if pkt.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		orig_ip6 = pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		orig_src = orig_ip6.SrcIP
		orig_dst = orig_ip6.DstIP
		flag_ipv6 = true
	} else {
		return fmt.Errorf("invalid packet recived"), nil

	}

	ret_eth := layers.Ethernet{
		SrcMAC:       orig_eth.DstMAC,
		DstMAC:       orig_eth.SrcMAC,
		EthernetType: eType,
	}

	ret_udp := layers.UDP{
		SrcPort: orig_udp.DstPort,
		DstPort: orig_udp.SrcPort,
	}

	// Parse Answers
	//  Crea la query di risposta
	for _, q := range orig_dns.Questions {
		// do not include types we can't handle
		// also ignore queries different from the target domain
		if !(q.Type == layers.DNSTypeA && q.Type == layers.DNSTypeAAAA) && !reflect.DeepEqual(q.Name, []byte(domain)) {
			continue
		}

		answers = append(answers,
			layers.DNSResourceRecord{
				Name:  []byte(q.Name),
				Type:  q.Type,
				Class: q.Class,
				TTL:   TTL,
				IP:    d_ip,
			})
	}

	ret_dns := layers.DNS{
		ID:        orig_dns.ID,
		QR:        true,
		AA:        true,
		RD:        true,
		RA:        true,
		OpCode:    layers.DNSOpCodeQuery,
		QDCount:   orig_dns.QDCount,
		ANCount:   uint16(len(answers)),
		Questions: orig_dns.Questions,
		Answers:   answers,
	}

	if flag_ipv6 {
		ip6 := layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolUDP,
			HopLimit:   64,
			SrcIP:      orig_dst,
			DstIP:      orig_src,
		}

		ret_udp.SetNetworkLayerForChecksum(&ip6)

		err, ret = Serialize(&ret_eth, &ip6, &ret_udp, &ret_dns)
	} else {
		ip4 := layers.IPv4{
			Protocol: layers.IPProtocolUDP,
			Version:  4,
			TTL:      64,
			SrcIP:    orig_dst,
			DstIP:    orig_src,
		}

		ret_udp.SetNetworkLayerForChecksum(&ip4)

		err, ret = Serialize(&ret_eth, &ip4, &ret_udp, &ret_dns)
	}

	if err != nil {
		return err, nil
	}

	return err, ret
}
