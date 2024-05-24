package packets

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestNewDNSReplyFromRequest(t *testing.T) {
	var data []byte

	m1, err := net.ParseMAC("00:00:00:00:00:00")
	//m2, err := net.ParseMAC("f:f:f:f:f:f")

	ip1, ip2 := net.ParseIP("0.0.0.0"), net.ParseIP("1.1.1.1")

	eth := layers.Ethernet{
		SrcMAC:       m1,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		TTL:      64,
		SrcIP:    ip1,
		DstIP:    ip2,
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(12345),
		DstPort: layers.UDPPort(53),
	}

	query := layers.DNSQuestion{
		Name:  []byte("dom"),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassAny,
	}

	dns := layers.DNS{
		ID:        0xabad,
		QR:        true,
		OpCode:    layers.DNSOpCodeQuery,
		QDCount:   1,
		Questions: []layers.DNSQuestion{query},
		Answers:   nil,
	}

	udp.SetNetworkLayerForChecksum(&ip4)
	err, raw := Serialize(&eth, &ip4, &udp, &dns)

	if err != nil {
		t.Error("Cannot create dns packet", err)
		return
	}

	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)

	if err, data = NewDNSReplyFromRequest(pkt, "dom", ip1, 0); err != nil {
		t.Error("NewDNSReply", err)
		return
	}

	res_pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	println(pkt.String())
	println(res_pkt.String())
}
