package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func vmessURL(t *testing.T, js string) string {
	t.Helper()
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
}

func TestIdentityVMessPortString(t *testing.T) {
	e := ProxyEntry{Scheme: "vmess", URL: vmessURL(t, `{"add":"1.2.3.4","port":"443","ps":"x"}`)}
	if got := e.Identity(); got != "vmess|1.2.3.4|443" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityVMessPortNumber(t *testing.T) {
	e := ProxyEntry{Scheme: "vmess", URL: vmessURL(t, `{"add":"1.2.3.4","port":443,"ps":"x"}`)}
	if got := e.Identity(); got != "vmess|1.2.3.4|443" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityVLESSLowercasesHost(t *testing.T) {
	e := ProxyEntry{Scheme: "vless", URL: "vless://uuid@Example.COM:8443?x=1#n"}
	if got := e.Identity(); got != "vless|example.com|8443" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentitySSSIP002(t *testing.T) {
	e := ProxyEntry{Scheme: "ss", URL: "ss://YWVzOnB3@1.2.3.4:8388#n"}
	if got := e.Identity(); got != "ss|1.2.3.4|8388" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentitySSLegacyBase64(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pass@5.6.7.8:443"))
	e := ProxyEntry{Scheme: "ss", URL: "ss://" + payload + "#n"}
	if got := e.Identity(); got != "ss|5.6.7.8|443" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityEmptyPort(t *testing.T) {
	e := ProxyEntry{Scheme: "trojan", URL: "trojan://p@host.com#n"}
	if got := e.Identity(); got != "trojan|host.com|" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityIPv6(t *testing.T) {
	e := ProxyEntry{Scheme: "vless", URL: "vless://u@[2001:db8::1]:443#n"}
	if got := e.Identity(); got != "vless|2001:db8::1|443" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityUnparseableIsEmpty(t *testing.T) {
	e := ProxyEntry{Scheme: "vless", URL: "not a url"}
	if got := e.Identity(); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityAliasHy2Normalized(t *testing.T) {
	a := ProxyEntry{Scheme: "hy2", URL: "hy2://u@1.2.3.4:443#A"}
	b := ProxyEntry{Scheme: "hysteria2", URL: "hysteria2://u@1.2.3.4:443#B"}
	if a.Identity() != b.Identity() {
		t.Fatalf("hy2 and hysteria2 must share identity: %q vs %q", a.Identity(), b.Identity())
	}
}

func TestIdentityAliasSocksNormalized(t *testing.T) {
	a := ProxyEntry{Scheme: "socks", URL: "socks://Og==:Og==@1.2.3.4:1080#A"}
	b := ProxyEntry{Scheme: "socks5", URL: "socks5://Og==:Og==@1.2.3.4:1080#B"}
	if a.Identity() != b.Identity() {
		t.Fatalf("socks and socks5 must share identity: %q vs %q", a.Identity(), b.Identity())
	}
}

func TestDedupeByAliasScheme(t *testing.T) {
	a := ProxyEntry{Scheme: "hy2", URL: "hy2://u@1.2.3.4:443#A"}
	b := ProxyEntry{Scheme: "hysteria2", URL: "hysteria2://u@1.2.3.4:443#B"}
	if got := dedupeByIdentity([]ProxyEntry{a, b}); len(got) != 1 {
		t.Fatalf("alias schemes must dedupe to 1, got %d", len(got))
	}
}

func TestSetVmessNameUnpaddedPayload(t *testing.T) {
	// Real node from docs/list2.txt: unpadded base64 payload (len%4==2).
	raw := "vmess://eyJ2IjoiMiIsInBzIjoiU0cgXHVkODNjXHVkZGY4XHVkODNjXHVkZGVjIFx1MjUwNyBWTUVTUy1UQ1AtTlRMUyAtIEFTLVZVTFRSIFx1MjUwNyA0NS4zMi4xMjAuMTczIiwiYWRkIjoiNDUuMzIuMTIwLjE3MyIsInBvcnQiOjQ0MywiaWQiOiJYRVhFVklMIiwiYWlkIjowLCJzY3kiOiJhdXRvIiwibmV0IjoidGNwIiwidHlwZSI6Im5vbmUifQ"
	if len(raw[len("vmess://"):])%4 == 0 {
		t.Fatal("test fixture unexpectedly padded")
	}
	got := setName(raw, "vmess", "", "SG 1 - Vultr")
	if got == raw {
		t.Fatal("unpadded vmess payload must be renamed, got original")
	}
	if vmessName(got) != "SG 1 - Vultr" {
		t.Fatalf("renamed ps = %q", vmessName(got))
	}
}

func TestDedupeByIdentityDeterministic(t *testing.T) {
	a := ProxyEntry{Scheme: "vless", URL: "vless://u@1.2.3.4:443#b"}
	b := ProxyEntry{Scheme: "vless", URL: "vless://u@1.2.3.4:443#a"}
	got1 := dedupeByIdentity([]ProxyEntry{a, b})
	got2 := dedupeByIdentity([]ProxyEntry{b, a})
	if len(got1) != 1 || len(got2) != 1 {
		t.Fatalf("len %d %d", len(got1), len(got2))
	}
	if got1[0].URL != got2[0].URL || got1[0].URL != b.URL {
		t.Fatalf("nondeterministic: %q %q", got1[0].URL, got2[0].URL)
	}
}

func TestDedupeByIdentityDropsUnparseable(t *testing.T) {
	got := dedupeByIdentity([]ProxyEntry{{Scheme: "vless", URL: "garbage"}})
	if len(got) != 0 {
		t.Fatalf("expected drop, got %d", len(got))
	}
}

func TestNameParts(t *testing.T) {
	cc, num, ok := nameParts("US 12 - Foo Bar")
	if !ok || cc != "US" || num != 12 {
		t.Fatalf("got %q %d %v", cc, num, ok)
	}
	if _, _, ok := nameParts("US - Foo"); ok {
		t.Fatal("malformed name should not parse")
	}
	if _, _, ok := nameParts(""); ok {
		t.Fatal("empty name should not parse")
	}
}

func TestParsePrevList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	vm := vmessURL(t, `{"add":"1.2.3.4","port":"443","ps":"US 1 - Foo"}`)
	content := "# Build date: x\n" +
		"vless://u@5.6.7.8:8443#DE 3 - Bar\n" +
		vm + "\n" +
		"garbage-line\n" +
		"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := parsePrevList(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].Identity != "vless|5.6.7.8|8443" || got[0].Name != "DE 3 - Bar" || got[0].CC != "DE" {
		t.Fatalf("bad first: %+v", got[0])
	}
	if got[1].Identity != "vmess|1.2.3.4|443" || got[1].Name != "US 1 - Foo" || got[1].CC != "US" {
		t.Fatalf("bad second: %+v", got[1])
	}
}

func TestParsePrevListMissingFile(t *testing.T) {
	got, err := parsePrevList(filepath.Join(t.TempDir(), "nope.txt"))
	if err != nil || got != nil {
		t.Fatalf("expected nil,nil got %v,%v", got, err)
	}
}

func TestBuildTestSetDedup(t *testing.T) {
	cand := []ProxyEntry{{Scheme: "vless", URL: "vless://u@1.2.3.4:443"}}
	prevDiff := []PrevEntry{{Identity: "vless|1.2.3.4|443", URL: "vless://old@1.2.3.4:443"}}
	if got := buildTestSet(cand, prevDiff); len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	prevSame := []PrevEntry{{Identity: "vless|1.2.3.4|443", URL: "vless://u@1.2.3.4:443"}}
	if got := buildTestSet(cand, prevSame); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
}

func TestMergeCarryForwardOldAlive(t *testing.T) {
	p := PrevEntry{Identity: "vless|1.2.3.4|443", URL: "vless://u@1.2.3.4:443#US 1 - Foo", Name: "US 1 - Foo", CC: "US"}
	got := mergeOutput([]PrevEntry{p}, nil, map[string]bool{p.URL: true})
	if len(got) != 1 || got[0].URL != p.URL {
		t.Fatalf("got %+v", got)
	}
}

func TestMergeRotatedCredentialKeepsName(t *testing.T) {
	p := PrevEntry{Identity: "vless|1.2.3.4|443", URL: "vless://old@1.2.3.4:443#US 1 - Foo", Name: "US 1 - Foo", CC: "US"}
	c := ProxyEntry{Scheme: "vless", URL: "vless://new@1.2.3.4:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Foo"}}
	got := mergeOutput([]PrevEntry{p}, []ProxyEntry{c}, map[string]bool{c.URL: true})
	if len(got) != 1 || got[0].URL != "vless://new@1.2.3.4:443#US 1 - Foo" {
		t.Fatalf("got %+v", got)
	}
}

func TestMergeOrphanDeadDropped(t *testing.T) {
	p := PrevEntry{Identity: "vless|1.2.3.4|443", URL: "vless://u@1.2.3.4:443#US 1 - Foo", Name: "US 1 - Foo", CC: "US"}
	got := mergeOutput([]PrevEntry{p}, nil, map[string]bool{})
	if len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestMergeMalformedNameCarriedAsIs(t *testing.T) {
	p := PrevEntry{Identity: "vless|1.2.3.4|443", URL: "vless://u@1.2.3.4:443#weird", Name: "weird", CC: ""}
	got := mergeOutput([]PrevEntry{p}, nil, map[string]bool{p.URL: true})
	if len(got) != 1 || got[0].URL != p.URL {
		t.Fatalf("got %+v", got)
	}
}

func TestMergeRotatedMalformedNamePreserved(t *testing.T) {
	p := PrevEntry{Identity: "vless|1.2.3.4|443", URL: "vless://old@1.2.3.4:443#weird", Name: "weird", CC: ""}
	c := ProxyEntry{Scheme: "vless", URL: "vless://new@1.2.3.4:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Foo"}}
	got := mergeOutput([]PrevEntry{p}, []ProxyEntry{c}, map[string]bool{c.URL: true})
	if len(got) != 1 || got[0].URL != "vless://new@1.2.3.4:443#weird" {
		t.Fatalf("malformed old name must be preserved as-is, got %+v", got)
	}
}

func TestMergeRotatedEmptyOldNameUsesCandidate(t *testing.T) {
	p := PrevEntry{Identity: "vless|1.2.3.4|443", URL: "vless://old@1.2.3.4:443", Name: "", CC: ""}
	c := ProxyEntry{Scheme: "vless", URL: "vless://new@1.2.3.4:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Foo"}}
	got := mergeOutput([]PrevEntry{p}, []ProxyEntry{c}, map[string]bool{c.URL: true})
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].URL != "vless://new@1.2.3.4:443#US 1 - Foo" {
		t.Fatalf("empty old name must fall back to candidate country, got %q", got[0].URL)
	}
	if got[0].CountryInfo.CountryCode != "US" {
		t.Fatalf("cc must be US, got %q", got[0].CountryInfo.CountryCode)
	}
}

func TestExtractAddressToleratesPercentInName(t *testing.T) {
	if got := extractAddress("vless", "vless://u@1.2.3.4:443#US 1 - 100% Off"); got != "1.2.3.4" {
		t.Fatalf("candidate with %% in name must still parse, got %q", got)
	}
}

func TestParsePrevListKeepsRawPercentName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	content := "vless://u@1.2.3.4:443#US 1 - 100% Off\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := parsePrevList(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].Name != "US 1 - 100% Off" {
		t.Fatalf("raw name must be kept, got %q", got[0].Name)
	}
}

func TestFilterPrevCountries(t *testing.T) {
	cfg.ExcludedCountries = map[string]bool{"RU": true}
	cfg.IncludedCountries = nil
	defer func() {
		cfg.ExcludedCountries = nil
		cfg.IncludedCountries = nil
	}()
	prev := []PrevEntry{
		{Identity: "a", Name: "RU 1 - X", CC: "RU"},
		{Identity: "b", Name: "US 1 - Y", CC: "US"},
		{Identity: "c", Name: "", CC: ""},
	}
	got := filterPrevCountries(prev)
	if len(got) != 1 || got[0].CC != "US" {
		t.Fatalf("expected only US, got %+v", got)
	}
}

func TestFilterPrevCountriesIncludedWhitelist(t *testing.T) {
	cfg.ExcludedCountries = nil
	cfg.IncludedCountries = map[string]bool{"US": true}
	defer func() {
		cfg.ExcludedCountries = nil
		cfg.IncludedCountries = nil
	}()
	prev := []PrevEntry{
		{Identity: "a", Name: "DE 1 - X", CC: "DE"},
		{Identity: "b", Name: "US 1 - Y", CC: "US"},
	}
	got := filterPrevCountries(prev)
	if len(got) != 1 || got[0].CC != "US" {
		t.Fatalf("got %+v", got)
	}
}

func TestFilterPrevCountriesParityWithCandidates(t *testing.T) {
	cfg.ExcludedCountries = nil
	cfg.IncludedCountries = nil
	prev := []PrevEntry{
		{Identity: "a", Name: "US 1 - Y", CC: "US"},
		{Identity: "b", Name: "", CC: ""},
		{Identity: "c", Name: "ZZ 1 - X", CC: "ZZ"},
	}
	cands := []ProxyEntry{
		{URL: "vless://u@1.2.3.4:443", CountryInfo: CountryInfo{CountryCode: "US"}},
		{URL: "vless://u@2.2.2.2:443", CountryInfo: CountryInfo{CountryCode: ""}},
		{URL: "vless://u@3.3.3.3:443", CountryInfo: CountryInfo{CountryCode: "ZZ"}},
	}
	if got := len(filterPrevCountries(prev)); got != len(filterCountries(cands)) {
		t.Fatalf("filter parity broken: prev=%d cand=%d", got, len(filterCountries(cands)))
	}
}

func TestMergeNumberReuseSmallestFree(t *testing.T) {
	p := PrevEntry{Identity: "vless|9.9.9.9|443", URL: "vless://u@9.9.9.9:443#US 2 - B", Name: "US 2 - B", CC: "US"}
	c := ProxyEntry{Scheme: "vless", URL: "vless://u@1.1.1.1:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Foo"}}
	got := mergeOutput([]PrevEntry{p}, []ProxyEntry{c}, map[string]bool{p.URL: true, c.URL: true})
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].URL != "vless://u@1.1.1.1:443#US 1 - Foo" {
		t.Fatalf("new node not numbered 1: %q", got[0].URL)
	}
	if got[1].URL != p.URL {
		t.Fatalf("carried not preserved: %q", got[1].URL)
	}
}

func TestMergeNoPrevNumbersSequentially(t *testing.T) {
	c1 := ProxyEntry{Scheme: "vless", URL: "vless://a@1.1.1.1:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Foo"}}
	c2 := ProxyEntry{Scheme: "vless", URL: "vless://b@2.2.2.2:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Bar"}}
	alive := map[string]bool{c1.URL: true, c2.URL: true}
	got := mergeOutput(nil, []ProxyEntry{c1, c2}, alive)
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].URL != "vless://a@1.1.1.1:443#US 1 - Foo" || got[1].URL != "vless://b@2.2.2.2:443#US 2 - Bar" {
		t.Fatalf("got %q %q", got[0].URL, got[1].URL)
	}
}

func TestMergeDeterministic(t *testing.T) {
	c1 := ProxyEntry{Scheme: "vless", URL: "vless://a@1.1.1.1:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Foo"}}
	c2 := ProxyEntry{Scheme: "vless", URL: "vless://b@2.2.2.2:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Bar"}}
	alive := map[string]bool{c1.URL: true, c2.URL: true}
	g1 := mergeOutput(nil, []ProxyEntry{c1, c2}, alive)
	g2 := mergeOutput(nil, []ProxyEntry{c2, c1}, alive)
	if len(g1) != len(g2) {
		t.Fatal("length differs")
	}
	for i := range g1 {
		if g1[i].URL != g2[i].URL {
			t.Fatalf("nondeterministic at %d: %q vs %q", i, g1[i].URL, g2[i].URL)
		}
	}
}
