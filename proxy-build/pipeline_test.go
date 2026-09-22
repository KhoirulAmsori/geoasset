package main

import (
	"encoding/base64"
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
