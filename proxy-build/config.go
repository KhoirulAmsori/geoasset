package main

import (
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

func DefaultConfig() Config {
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
	if parsed, err := utils.NewUnsignedRanges[uint16](cfg.ExpectedStatus); err == nil {
		cfg.ExpectedRanges = parsed
	}
	return cfg
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
