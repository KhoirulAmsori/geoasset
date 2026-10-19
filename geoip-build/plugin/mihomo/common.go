package mihomo

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Loyalsoldier/geoip/lib"
	"go4.org/netipx"
)

// entryPrefixes mengembalikan CIDR milik entry. hanyaIPType membatasi hasil ke
// satu keluarga alamat, memakai opsi lib yang sama seperti output maxmindMMDB.
func entryPrefixes(entry *lib.Entry, onlyIPType lib.IPType) ([]netip.Prefix, error) {
	var ignoreIPType lib.IgnoreIPOption
	switch onlyIPType {
	case lib.IPv4:
		ignoreIPType = lib.IgnoreIPv6
	case lib.IPv6:
		ignoreIPType = lib.IgnoreIPv4
	}

	cidrList, err := entry.MarshalText(ignoreIPType)
	if err != nil {
		return nil, err
	}

	prefixes := make([]netip.Prefix, 0, len(cidrList))
	for _, cidr := range cidrList {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("entry %s has invalid CIDR %q: %w", entry.GetName(), cidr, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	return prefixes, nil
}

// mergedRanges menyatukan prefix yang bersebelahan. Mihomo melakukan hal yang
// sama pada cidr.IpCidrSet.Merge, jadi jumlah range harus cocok agar isi
// berkas MRS bisa dibandingkan dengan hasil meta-rules-converter.
func mergedRanges(prefixes []netip.Prefix) ([]netipx.IPRange, error) {
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(prefix)
	}

	set, err := builder.IPSet()
	if err != nil {
		return nil, err
	}

	return set.Ranges(), nil
}

// filterList memakai wantedList bila diisi; jika tidak, seluruh list di
// container dipakai dikurangi excludedList. Nama selalu huruf besar agar
// cocok dengan key container.
func filterList(container lib.Container, want, exclude []string) []string {
	excludeMap := make(map[string]bool)
	for _, item := range exclude {
		if item = strings.ToUpper(strings.TrimSpace(item)); item != "" {
			excludeMap[item] = true
		}
	}

	list := make([]string, 0, len(want))
	for _, item := range want {
		if item = strings.ToUpper(strings.TrimSpace(item)); item != "" && !excludeMap[item] {
			list = append(list, item)
		}
	}
	slices.Sort(list)
	if len(list) > 0 {
		return list
	}

	all := make([]string, 0, 300)
	for entry := range container.Loop() {
		name := entry.GetName()
		if excludeMap[name] {
			continue
		}
		all = append(all, name)
	}
	slices.Sort(all)

	return all
}
