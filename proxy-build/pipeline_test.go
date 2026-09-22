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
