package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	SourcesFile          string
	GeoIPCountryDB       string
	GeoIPASNDB           string
	MaxThreadCount       int
	Timeout              time.Duration
	MinActiveProxies     int
	TestURL              string
	ExpectedStatus       string
	ConcurrentDNS        int
	IncludedCountries    map[string]bool
	ExcludedCountries    map[string]bool
	EnableDebug          bool
	CollectionAdjustment int
}

func DefaultConfig() Config {
	cfg := Config{
		SourcesFile:          envOr("SourcesFile", "Asset/sources.txt"),
		GeoIPCountryDB:       envOr("GeoLiteCountryDbPath", "Asset/GeoLite2-Country.mmdb"),
		GeoIPASNDB:           envOr("GeoLiteAsnDbPath", "Asset/GeoLite2-ASN.mmdb"),
		MaxThreadCount:       envInt("MaxThreadCount", 64),
		Timeout:              time.Duration(envInt("Timeout", 8000)) * time.Millisecond,
		MinActiveProxies:     envInt("MinActiveProxies", 10),
		TestURL:              envOr("TestUrl", "https://www.youtube.com/generate_204"),
		ExpectedStatus:       envOr("ExpectedStatus", "200-204"),
		ConcurrentDNS:        envInt("ConcurrentDNS", 32),
		IncludedCountries:    envSet("IncludedCountry"),
		ExcludedCountries:    envSet("ExcludedCountry"),
		EnableDebug:          envBool("EnableDebug", false),
		CollectionAdjustment: envInt("CollectionAdjustment", 0),
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
