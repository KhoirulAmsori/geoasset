package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/utils"
)

type Config struct {
	SourcesFile          string
	GeoIPCountryDB       string
	GeoIPASNDB           string
	MaxThreadCount       int
	Timeout              time.Duration
	MinActiveProxies     int
	MaxProxiesPerCountry int
	TestURL              string
	ExpectedStatus       string
	ExpectedRanges       utils.IntRanges[uint16]
	RetryCount           int
	ConcurrentDNS        int
	PreviousListFile     string
	IncludedCountries    map[string]bool
	ExcludedCountries    map[string]bool
	ExcludedProtocols    map[string]bool
	EnableDebug          bool

	SpeedTestEnabled     bool
	SpeedTestURL         string
	SpeedTestFallbackURL string
	SpeedTestMaxBytes    int64
	SpeedTestTimeout     time.Duration
	SpeedTestThreadCount int
	SpeedTestMaxNodes    int
	SpeedTestInput       string
	SpeedTestReportBase  string
}

// DefaultConfig membaca seluruh knob dari environment variable. Satu-satunya
// kegagalan yang mungkin dikembalikan adalah ExpectedStatus yang tidak bisa
// diparse: dibiarkan lolos, rentang status menjadi kosong dan mihomo
// (adapter.Proxy.URLTest) memperlakukan expectedStatus == nil sebagai "terima
// status apa pun", sehingga proxy yang menjawab 407/500 pun dianggap hidup.
func DefaultConfig() (Config, error) {
	cfg := Config{
		SourcesFile:          envOr("SourcesFile", "Asset/sources.txt"),
		GeoIPCountryDB:       envOr("GeoLiteCountryDbPath", "Asset/GeoLite2-Country.mmdb"),
		GeoIPASNDB:           envOr("GeoLiteAsnDbPath", "Asset/GeoLite2-ASN.mmdb"),
		MaxThreadCount:       envInt("MaxThreadCount", 512),
		Timeout:              time.Duration(envInt("Timeout", 8000)) * time.Millisecond,
		MinActiveProxies:     envInt("MinActiveProxies", 10),
		MaxProxiesPerCountry: envInt("MaxProxiesPerCountry", 0),
		TestURL:              envOr("TestUrl", "https://www.youtube.com/generate_204"),
		ExpectedStatus:       envOr("ExpectedStatus", "200-204"),
		RetryCount:           envInt("RetryCount", 3),
		ConcurrentDNS:        envInt("ConcurrentDNS", 128),
		PreviousListFile:     envOr("PreviousListFile", ""),
		IncludedCountries:    envSet("IncludedCountry"),
		ExcludedCountries:    envSet("ExcludedCountry"),
		ExcludedProtocols:    envProtocolSet("ExcludedProtocol"),
		EnableDebug:          envBool("EnableDebug", false),

		SpeedTestEnabled:     envBool("SpeedTestEnabled", true),
		SpeedTestURL:         envOr("SpeedTestURL", "https://speed.cloudflare.com/__down?bytes=10000000"),
		SpeedTestFallbackURL: envOr("SpeedTestFallbackURL", "https://proof.ovh.net/files/100Mb.dat"),
		SpeedTestMaxBytes:    int64(envInt("SpeedTestMaxBytes", 3_000_000)),
		SpeedTestTimeout:     time.Duration(envInt("SpeedTestTimeout", 5000)) * time.Millisecond,
		SpeedTestThreadCount: envInt("SpeedTestThreadCount", 16),
		SpeedTestMaxNodes:    envInt("SpeedTestMaxNodes", 0),
		SpeedTestInput:       envOr("SpeedTestInput", "list.txt"),
		SpeedTestReportBase:  envOr("SpeedTestReportBase", "speed"),
	}
	if cfg.SpeedTestThreadCount < 1 {
		cfg.SpeedTestThreadCount = 1
	}
	if cfg.SpeedTestMaxBytes < 0 {
		cfg.SpeedTestMaxBytes = 0
	}
	if cfg.RetryCount < 0 {
		cfg.RetryCount = 0
	}
	parsed, err := utils.NewUnsignedRanges[uint16](cfg.ExpectedStatus)
	if err != nil || len(parsed) == 0 {
		return Config{}, fmt.Errorf("invalid ExpectedStatus %q (example of valid value: \"200-204\")", cfg.ExpectedStatus)
	}
	cfg.ExpectedRanges = parsed
	return cfg, nil
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
	}
	return fallback
}

func envSet(key string) map[string]bool {
	m := map[string]bool{}
	if v, ok := os.LookupEnv(key); ok {
		for _, part := range strings.Split(v, ",") {
			c := strings.ToUpper(strings.TrimSpace(part))
			if c != "" {
				m[c] = true
			}
		}
	}
	return m
}

// envProtocolSet reads a comma-separated list of scheme names and normalizes
// each through the scheme-alias table (hy2 -> hysteria2, socks -> socks5) so
// that a user may write either spelling.
func envProtocolSet(key string) map[string]bool {
	m := map[string]bool{}
	if v, ok := os.LookupEnv(key); ok {
		for _, part := range strings.Split(v, ",") {
			c := normalizeScheme(strings.TrimSpace(part))
			if c != "" {
				m[c] = true
			}
		}
	}
	return m
}
