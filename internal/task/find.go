// ==============================================================================
// File name:     find.go
// Description:   MAC / IP locator: finds the access port a host is attached to.
// License:       MIT
// ==============================================================================
package task

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"netops/internal/inventory"
	"netops/internal/vendor"
)

// LocatorCapability admits platforms that can answer an ARP query (byMAC
// false) or a MAC table query (byMAC true).
func LocatorCapability(byMAC bool) Capability {
	return func(p *vendor.Profile) (bool, string) {
		l, ok := p.Locator()
		switch {
		case !ok:
			return false, "no ARP or MAC table command is defined for it"
		case byMAC && l.FindMACCommand("00:00:00:00:00:01") == "":
			return false, "it has no MAC address table (it is a layer-3 device)"
		case !byMAC && l.FindIPCommand("0.0.0.1") == "":
			return false, "it has no ARP table command"
		}
		return true, ""
	}
}

// ARPMatch is an IP-to-MAC mapping learnt from a device's ARP table.
type ARPMatch struct {
	Device inventory.Device
	Record vendor.LocatorRecord
}

// Hit is a MAC table entry for the wanted address.
type Hit struct {
	Device inventory.Device
	Record vendor.LocatorRecord
	// Uplink is set when the port is a trunk or link aggregate, i.e. a path
	// toward the host rather than the port the host is plugged into.
	Uplink bool
	Why    string // "trunk" / "port-channel" when Uplink
}

// FindSink gathers what the locator handlers learn across devices.
type FindSink struct {
	mu   sync.Mutex
	arp  []ARPMatch
	hits []Hit
}

// ARP returns the IP-to-MAC matches, in device order.
func (s *FindSink) ARP() []ARPMatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]ARPMatch(nil), s.arp...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Device.Hostname < out[j].Device.Hostname })
	return out
}

// Hits returns the MAC table entries, access ports first.
func (s *FindSink) Hits() []Hit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Hit(nil), s.hits...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Uplink != out[j].Uplink {
			return !out[i].Uplink
		}
		return out[i].Device.Hostname < out[j].Device.Hostname
	})
	return out
}

// ARPHandler looks ip up in each device's ARP table.
func (s *FindSink) ARPHandler(ip string) Handler {
	return func(ctx context.Context, env *HandlerEnv) (string, error) {
		l, ok := env.Job.Profile.Locator()
		if !ok {
			return "", opErrorf(CatUnsupportedOp, "no locator for %s", env.Job.Profile.Display)
		}
		cmd := l.FindIPCommand(ip)
		if cmd == "" {
			return "", opErrorf(CatUnsupportedOp, "no ARP query on %s", env.Job.Profile.Display)
		}
		out, err := env.Run(ctx, cmd)
		if err != nil {
			return "", err
		}
		var found []string
		for _, r := range l.ParseIP(out) {
			if r.IP != ip || r.MAC == "" {
				continue
			}
			s.mu.Lock()
			s.arp = append(s.arp, ARPMatch{Device: env.Job.Device, Record: r})
			s.mu.Unlock()
			found = append(found, fmt.Sprintf("%s on %s", r.MAC, dash(r.Interface)))
		}
		if len(found) == 0 {
			return "not in the ARP table", nil
		}
		return strings.Join(found, "; "), nil
	}
}

// MACHandler looks mac (any notation) up in each device's MAC address table
// and classifies every entry as an access port or an uplink. CPU and other
// internal pseudo-ports are dropped.
func (s *FindSink) MACHandler(mac string) Handler {
	norm, nerr := vendor.NormalizeMAC(mac)
	want := vendor.FormatMAC(norm, vendor.MACColon)
	return func(ctx context.Context, env *HandlerEnv) (string, error) {
		if nerr != nil {
			return "", opErrorf(CatSyntaxError, "%v", nerr)
		}
		l, ok := env.Job.Profile.Locator()
		if !ok {
			return "", opErrorf(CatUnsupportedOp, "no locator for %s", env.Job.Profile.Display)
		}
		cmd := l.FindMACCommand(want)
		if cmd == "" {
			return "", opErrorf(CatUnsupportedOp, "no MAC table query on %s", env.Job.Profile.Display)
		}
		out, err := env.Run(ctx, cmd)
		if err != nil {
			return "", err
		}
		var recs []vendor.LocatorRecord
		for _, r := range l.ParseMAC(out) {
			if r.MAC == want && !vendor.IsInternalPort(r.Interface) {
				recs = append(recs, r)
			}
		}
		if len(recs) == 0 {
			return "not in the MAC table", nil
		}
		trunks := s.trunkSet(ctx, env, l)
		var where []string
		for _, r := range recs {
			h := Hit{Device: env.Job.Device, Record: r}
			switch {
			case vendor.IsAggregatePort(r.Interface):
				h.Uplink, h.Why = true, "port-channel"
			case trunks[strings.ToLower(r.Interface)]:
				h.Uplink, h.Why = true, "trunk"
			}
			s.mu.Lock()
			s.hits = append(s.hits, h)
			s.mu.Unlock()
			tag := ""
			if h.Uplink {
				tag = " (" + h.Why + ")"
			}
			where = append(where, fmt.Sprintf("%s%s", r.Interface, tag))
		}
		return "learned on " + strings.Join(where, ", "), nil
	}
}

// trunkSet asks platforms that can tell which ports are trunks. A failure
// only means "unknown": the entry is then reported as an access candidate.
func (s *FindSink) trunkSet(ctx context.Context, env *HandlerEnv, l vendor.NetworkLocator) map[string]bool {
	td, ok := l.(vendor.TrunkDetector)
	if !ok || td.TrunkPortsCommand() == "" {
		return nil
	}
	out, err := env.Run(ctx, td.TrunkPortsCommand())
	if err != nil {
		env.Log.Warnf(env.Host(), "trunk detection unavailable (%v); uplinks cannot be told from access ports on this device", err)
		return nil
	}
	set := map[string]bool{}
	for _, p := range td.ParseTrunkPorts(out) {
		set[strings.ToLower(p)] = true
	}
	return set
}
