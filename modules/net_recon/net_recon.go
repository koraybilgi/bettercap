package net_recon

import (
	"time"

	"github.com/bettercap/bettercap/modules/utils"

	"github.com/bettercap/bettercap/network"
	"github.com/bettercap/bettercap/session"
)

type Discovery struct {
	session.SessionModule
	selector     *utils.ViewSelector
	oldEndpoints map[string]network.Endpoint
}

func NewDiscovery(s *session.Session) *Discovery {
	mod := &Discovery{
		SessionModule: session.NewSessionModule("net.recon", s),
		oldEndpoints:  make(map[string]network.Endpoint),
	}

	mod.AddHandler(session.NewModuleHandler("net.recon on", "",
		"Start network hosts discovery.",
		func(args []string) error {
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("net.recon off", "",
		"Stop network hosts discovery.",
		func(args []string) error {
			return mod.Stop()
		}))

	mod.AddHandler(session.NewModuleHandler("net.clear", "",
		"Clear all endpoints collected by the hosts discovery module.",
		func(args []string) error {
			mod.Session.Lan.Clear()
			return nil
		}))

	mod.AddParam(session.NewBoolParameter("net.show.meta",
		"false",
		"If true, the net.show command will show all metadata collected about each endpoint."))

	mod.AddHandler(session.NewModuleHandler("net.show", "",
		"Show cache hosts list (default sorting by ip).",
		func(args []string) error {
			return mod.Show("")
		}))

	mod.AddHandler(session.NewModuleHandler("net.show ADDRESS1, ADDRESS2", `net.show (.+)`,
		"Show information about a specific comma separated list of addresses (by IP or MAC).",
		func(args []string) error {
			return mod.Show(args[0])
		}))

	mod.AddHandler(session.NewModuleHandler("net.show.meta ADDRESS1, ADDRESS2", `net\.show\.meta (.+)`,
		"Show meta information about a specific comma separated list of addresses (by IP or MAC).",
		func(args []string) error {
			return mod.showMeta(args[0])
		}))

	mod.selector = utils.ViewSelectorFor(&mod.SessionModule, "net.show", []string{"ip", "mac", "seen", "sent", "rcvd"},
		"ip asc")

	return mod
}

func (mod Discovery) Name() string {
	return "net.recon"
}

func (mod Discovery) Description() string {
	return "Read periodically the ARP cache in order to monitor for new hosts on the network."
}

func (mod Discovery) Author() string {
	return "Simone Margaritelli <evilsocket@gmail.com>"
}

func (mod *Discovery) runDiff(currentArpTable network.ArpTable) {
	// check for endpoints who disappeared
	var removeList network.ArpTable = make(network.ArpTable)

	/*
		La tabella di CACHE viene letteralmente dal comando `arp -a`, parsato.
		Quando si fa il `remove` dalla LAN, l'host non viene realmente rimosso
		fino a quando ttl = 0 (vedi network/lan.go),
		Dopo 10 tentativi di Remove() (ovvero 10 secondi e 10 letture da `arp -a`)
		LAN rimuove realmente l'host.
		La natura del problema risiede nella differenza tra il ttl del sistema operativo
		e il ttl di LAN. Per il sistema operativo un host è inattivo molto prima di
		LAN, pertanto verrà reinserito piu volte in oldEndpoints.
	*/

	mod.Session.Lan.EachHost(func(mac string, e *network.Endpoint) {
		endpoint_ip := e.IpAddress
		client_mac, found := currentArpTable[endpoint_ip]
		mod.Warning("IP: %s - CMAC: %s HMAC: %s - Found: %s", endpoint_ip, client_mac, e.HwAddress, found)

		if !found || (client_mac != e.HwAddress) { // not found or changed
			removeList[mac] = e.IpAddress
		} /* else if _, found := mod.oldEndpoints[mac]; found { // found and unchanged
			delete(mod.oldEndpoints, mac)
			mod.Warning("Removed %s -> %s from old endpoint", mac, e_ip)
		}*/
	})

	for mac, ip := range removeList {
		endpoint := *mod.Session.Lan.GetByIp(ip)
		if hard_remove := mod.Session.Lan.Remove(ip, mac); hard_remove {
			mod.oldEndpoints[mac] = endpoint
			//mod.Warning("Added %s -> %s to old endpoint len: %v", mac, ip, len(mod.oldEndpoints))

		}
	}

	// now check for new friends ^_^
	for ip, mac := range currentArpTable {
		if found := mod.Session.Lan.AddIfNew(ip, mac); found == nil && !mod.Session.Lan.ShouldIgnore(ip, mac) {
			delete(mod.oldEndpoints, mac)
			mod.Warning("FOUND %s %s oldEndpoints: %v", ip, mac, len(mod.oldEndpoints))
		}
	}
}

func (mod *Discovery) Configure() error {
	return nil
}

func (mod *Discovery) Start() error {
	if err := mod.Configure(); err != nil {
		return err
	}

	return mod.SetRunning(true, func() {
		every := time.Duration(1) * time.Second
		iface := mod.Session.Interface.Name()
		for mod.Running() {
			if table, err := network.ArpUpdate(iface); err != nil {
				mod.Error("%s", err)
			} else {
				mod.runDiff(table)
			}
			time.Sleep(every)
		}
	})
}

func (mod *Discovery) Stop() error {
	return mod.SetRunning(false, nil)
}