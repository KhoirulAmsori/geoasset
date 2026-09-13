package main

import (
	"net"
	"net/netip"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

type CountryResolver struct {
	country    *geoip2.Reader
	asn        *geoip2.Reader
	sem        chan struct{}
	mu         sync.Mutex
	ipCache    map[string]netip.Addr
	entryCache map[string]CountryInfo
}

type CountryInfo struct {
	CountryCode string
	CountryName string
	Isp         string
	Address     string
}

func OpenCountryResolver(countryDB, asnDB string, concurrentDNS int) (*CountryResolver, error) {
	country, err := geoip2.Open(countryDB)
	if err != nil {
		return nil, err
	}
	asn, err := geoip2.Open(asnDB)
	if err != nil {
		country.Close()
		return nil, err
	}
	return &CountryResolver{
		country:    country,
		asn:        asn,
		sem:        make(chan struct{}, concurrentDNS),
		ipCache:    map[string]netip.Addr{},
		entryCache: map[string]CountryInfo{},
	}, nil
}

func (r *CountryResolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.country != nil {
		r.country.Close()
	}
	if r.asn != nil {
		r.asn.Close()
	}
}

func (r *CountryResolver) Resolve(entryKey, address string) CountryInfo {
	if v, ok := func() (CountryInfo, bool) {
		r.mu.Lock()
		defer r.mu.Unlock()
		v, ok := r.entryCache[entryKey]
		return v, ok
	}(); ok {
		return v
	}

	info := r.resolveSlow(address)
	func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.entryCache) < 200000 {
			r.entryCache[entryKey] = info
		}
	}()
	return info
}

func (r *CountryResolver) resolveSlow(address string) CountryInfo {
	domain := address
	var ip netip.Addr
	if a, err := netip.ParseAddr(address); err != nil {
		if cached, ok := r.cachedIP(address); ok {
			ip = cached
		} else {
			ip = r.lookupIP(address)
			r.storeIP(address, ip)
		}
	} else {
		ip = a
	}

	if !ip.IsValid() || isPrivateOrReserved(ip) {
		return CountryInfo{CountryCode: "ZZ"}
	}

	ipNet := net.IP(ip.AsSlice())
	country, err := r.country.Country(ipNet)
	if err != nil {
		country = nil
	}
	asn, err := r.asn.ASN(ipNet)
	if err != nil {
		asn = nil
	}

	var cc, cn, isp string
	if country != nil {
		cc = country.Country.IsoCode
		cn = country.Country.Names["en"]
	}
	if asn != nil {
		isp = asn.AutonomousSystemOrganization
	}
	if cc == "" {
		cc = "ZZ"
	}
	return CountryInfo{
		CountryCode: cc,
		CountryName: cn,
		Isp:         isp,
		Address:     domain,
	}
}

func (r *CountryResolver) cachedIP(domain string) (netip.Addr, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.ipCache[domain]
	return a, ok
}

func (r *CountryResolver) storeIP(domain string, a netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ipCache) >= 100000 {
		return
	}
	r.ipCache[domain] = a
}

func (r *CountryResolver) lookupIP(domain string) netip.Addr {
	r.sem <- struct{}{}
	defer func() { <-r.sem }()

	addrs, err := net.LookupIP(domain)
	if err != nil {
		return netip.Addr{}
	}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.To4()); ok {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}

func isPrivateOrReserved(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip.Is4() {
		bytes := ip.As4()
		if bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127 {
			return true
		}
	}
	return false
}

func splitHost(address string) string {
	if h, _, err := net.SplitHostPort(address); err == nil {
		return h
	}
	return address
}
