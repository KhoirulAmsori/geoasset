package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigMenolakExpectedStatusRusak(t *testing.T) {
	t.Setenv("ExpectedStatus", "sana-sini")
	if _, err := DefaultConfig(); err == nil {
		t.Fatal("ExpectedStatus tidak valid seharusnya error, bukan diam-diam meloloskan semua status")
	}
}

func TestDefaultConfigMenolakExpectedStatusKosong(t *testing.T) {
	t.Setenv("ExpectedStatus", "0-0")
	if _, err := DefaultConfig(); err != nil {
		t.Fatalf("rentang valid seharusnya diterima: %v", err)
	}
}

func TestCountryAllowedTanpaFilterMenahanZZ(t *testing.T) {
	cfg.IncludedCountries = nil
	cfg.ExcludedCountries = map[string]bool{}
	defer func() { cfg.ExcludedCountries = nil }()

	// Tanpa include/exclude, node gagal-lokasi ikut dites (bukti hidup =
	// koneksi, bukan negara).
	for _, cc := range []string{"", "ZZ", "Unknown", "US"} {
		if !countryAllowed(cc) {
			t.Errorf("cc=%q seharusnya lolos saat tidak ada filter", cc)
		}
	}
}

func TestCountryAllowedDenganFilterMembuangYangTakDiketahui(t *testing.T) {
	cfg.IncludedCountries = map[string]bool{"US": true}
	defer func() { cfg.IncludedCountries = nil }()

	if countryAllowed("ZZ") || countryAllowed("") {
		t.Error("node tanpa negara tidak bisa dibuktikan masuk whitelist, harus dibuang")
	}
	if !countryAllowed("US") {
		t.Error("US seharusnya lolos whitelist")
	}
}

func TestAttemptTimeout(t *testing.T) {
	old := cfg.Timeout
	cfg.Timeout = 3 * time.Second
	defer func() { cfg.Timeout = old }()

	if got := attemptTimeout(0); got != 3*time.Second {
		t.Errorf("attempt pertama harus durasi penuh, got %v", got)
	}
	if got := attemptTimeout(1); got != 1500*time.Millisecond {
		t.Errorf("retry harus setengah, got %v", got)
	}

	// Timeout kecil (<= 2s) tidak dipangkas lagi supaya retry tidak jadi ~0.
	cfg.Timeout = time.Second
	if got := attemptTimeout(2); got != time.Second {
		t.Errorf("timeout kecil tidak boleh dipangkas, got %v", got)
	}
}

func TestCullBySpeed(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "list.txt")
	oldInput, oldMin := cfg.SpeedTestInput, cfg.MinActiveProxies
	cfg.SpeedTestInput = listPath
	cfg.MinActiveProxies = 1
	defer func() { cfg.SpeedTestInput, cfg.MinActiveProxies = oldInput, oldMin }()

	entries := []PrevEntry{
		{URL: "vless://a@1.1.1.1:443#US 1 - A"},
		{URL: "vless://b@2.2.2.2:443#US 2 - B"},
		{URL: "trojan://c@3.3.3.3:443#SG 1 - C"},
	}
	results := []SpeedResult{
		{BytesPerSec: 100},                 // hidup
		{Error: "read failed: EOF"},        // mati — harus dibuang
		{BytesPerSec: 9000, Country: "SG"}, // hidup
	}

	if err := writeProxyList(listPath, []ProxyEntry{{URL: entries[0].URL}, {URL: entries[1].URL}, {URL: entries[2].URL}}, true); err != nil {
		t.Fatal(err)
	}
	cullBySpeed(entries, results, true)

	b, err := os.ReadFile(listPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, entries[1].URL) {
		t.Errorf("node gagal speed masih ada di list:\n%s", got)
	}
	if !strings.Contains(got, entries[0].URL) || !strings.Contains(got, entries[2].URL) {
		t.Errorf("survivor hilang:\n%s", got)
	}
}

func TestCullBySpeedLewatiSaatCakupanTidakPenuh(t *testing.T) {
	oldInput := cfg.SpeedTestInput
	cfg.SpeedTestInput = filepath.Join(t.TempDir(), "jangan-disentuh.txt")
	defer func() { cfg.SpeedTestInput = oldInput }()

	entries := []PrevEntry{{URL: "vless://a@1.1.1.1:443"}}
	cullBySpeed(entries, []SpeedResult{}, false)
	if _, err := os.Stat(cfg.SpeedTestInput); err == nil {
		t.Fatal("list tidak boleh ditulis ulang saat cakupan tes tidak penuh")
	}
}

func TestCullBySpeedLewatiSaatProbeCurigaMati(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "list.txt")
	oldInput, oldMin := cfg.SpeedTestInput, cfg.MinActiveProxies
	cfg.SpeedTestInput = listPath
	cfg.MinActiveProxies = 5
	defer func() { cfg.SpeedTestInput, cfg.MinActiveProxies = oldInput, oldMin }()

	entries := []PrevEntry{{URL: "vless://a@1.1.1.1:443"}, {URL: "vless://b@2.2.2.2:443"}}
	results := []SpeedResult{{Error: "timeout"}, {Error: "timeout"}}

	if err := writeProxyList(listPath, []ProxyEntry{{URL: entries[0].URL}, {URL: entries[1].URL}}, true); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(listPath)
	cullBySpeed(entries, results, true)
	after, _ := os.ReadFile(listPath)

	if string(before) != string(after) {
		t.Error("survivor di bawah MinActiveProxies = probe curiga bermasalah, list harus utuh")
	}
}
