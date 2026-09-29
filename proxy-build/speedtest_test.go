package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpeedProbeMetadataHTTPS(t *testing.T) {
	m, err := speedProbeMetadata("https://speed.cloudflare.com/__down?bytes=1")
	if err != nil {
		t.Fatal(err)
	}
	if m.Host != "speed.cloudflare.com" || m.DstPort != 443 {
		t.Fatalf("got host=%q port=%d", m.Host, m.DstPort)
	}
}

func TestSpeedProbeMetadataHTTP(t *testing.T) {
	m, err := speedProbeMetadata("http://example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	if m.Host != "example.com" || m.DstPort != 80 {
		t.Fatalf("got host=%q port=%d", m.Host, m.DstPort)
	}
}

func TestSpeedProbeMetadataRejectsBadScheme(t *testing.T) {
	if _, err := speedProbeMetadata("ftp://example.com/x"); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestHumanLatency(t *testing.T) {
	if got := humanLatency(38); got != "38 ms" {
		t.Fatalf("got %q", got)
	}
	if got := humanLatency(0); got != "-" {
		t.Fatalf("zero latency must render dash, got %q", got)
	}
}

func TestHumanSpeed(t *testing.T) {
	if got := humanSpeed(9_420_000); got != "9.42 MB/s" {
		t.Fatalf("got %q", got)
	}
	if got := humanSpeed(0); got != "-" {
		t.Fatalf("zero speed must render dash, got %q", got)
	}
}

func TestSortSpeedResultsRanksOkBySpeed(t *testing.T) {
	results := []SpeedResult{
		{Name: "slow", BytesPerSec: 1_000_000, LatencyMS: 10},
		{Name: "dead", Error: "timeout"},
		{Name: "fast", BytesPerSec: 9_000_000, LatencyMS: 50},
	}
	sortSpeedResults(results)
	if results[0].Name != "fast" || results[1].Name != "slow" || results[2].Name != "dead" {
		t.Fatalf("bad order: %+v", results)
	}
}

func TestSortSpeedResultsLatencyTieBreak(t *testing.T) {
	results := []SpeedResult{
		{Name: "b", BytesPerSec: 5_000_000, LatencyMS: 90},
		{Name: "a", BytesPerSec: 5_000_000, LatencyMS: 20},
	}
	sortSpeedResults(results)
	if results[0].Name != "a" {
		t.Fatalf("lower latency must win tie, got %+v", results)
	}
}

func TestFormatSpeedReportContainsHeaderAndCounts(t *testing.T) {
	results := []SpeedResult{
		{Name: "A", Protocol: "ss", LatencyMS: 38, BytesPerSec: 9_420_000},
		{Name: "B", Protocol: "vless", LatencyMS: 55, BytesPerSec: 6_100_000},
		{Name: "C", Protocol: "trojan", Error: "timeout"},
	}
	sortSpeedResults(results)
	report := formatSpeedReport(results, "https://speed.cloudflare.com/__down")

	if !strings.Contains(report, "# measured 3, ok 2, failed 1") {
		t.Fatalf("missing counts:\n%s", report)
	}
	if !strings.Contains(report, "A") || !strings.Contains(report, "9.42 MB/s") {
		t.Fatalf("missing ok row:\n%s", report)
	}
	ai, bi := strings.Index(report, "A"), strings.Index(report, "B")
	if ai < 0 || bi < 0 || ai > bi {
		t.Fatalf("ok rows not ranked by speed:\n%s", report)
	}
	if !strings.Contains(report, "# failed") || !strings.Contains(report, "timeout") {
		t.Fatalf("missing failed section:\n%s", report)
	}
}

func TestWriteSpeedJSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "speed.json")
	results := []SpeedResult{
		{Name: "A", Country: "SG", Protocol: "ss", Address: "1.2.3.4:443", LatencyMS: 38, Bytes: 100, BytesPerSec: 9_420_000},
		{Name: "C", Protocol: "trojan", Error: "timeout"},
	}
	if err := writeSpeedJSON(path, results); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []SpeedResult
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "A" || got[0].BytesPerSec != 9_420_000 || got[1].Error != "timeout" {
		t.Fatalf("bad round trip: %+v", got)
	}
}

func TestBytesPerSecOf(t *testing.T) {
	// 3 MB over 600 ms must be ~5 MB/s, not divided by the TTFB window.
	if got := bytesPerSecOf(3_000_000, 600); got != 5_000_000 {
		t.Fatalf("got %d", got)
	}
	if got := bytesPerSecOf(3_000_000, 0); got != 0 {
		t.Fatalf("zero window must yield 0, got %d", got)
	}
	if got := bytesPerSecOf(0, 600); got != 0 {
		t.Fatalf("zero bytes must yield 0, got %d", got)
	}
}

func TestShortErrStripsHTTPWrapper(t *testing.T) {
	got := shortErr(errors.New(`Get "https://speed.cloudflare.com/x": EOF`))
	if got != "EOF" {
		t.Fatalf("got %q", got)
	}
	got = shortErr(errors.New("some error: context deadline exceeded"))
	if got != "timeout" {
		t.Fatalf("timeout must normalize, got %q", got)
	}
}

func TestJSONKeepsInputOrderWhileReportRanks(t *testing.T) {
	// Simulate measureAll: results in input order (fast node listed first in
	// the input must stay first in JSON even though the report ranks by speed).
	slow := SpeedResult{Name: "zslow", BytesPerSec: 100, LatencyMS: 900}
	fast := SpeedResult{Name: "afast", BytesPerSec: 9_000_000, LatencyMS: 50}
	inputOrder := []SpeedResult{slow, fast}

	ranked := make([]SpeedResult, len(inputOrder))
	copy(ranked, inputOrder)
	sortSpeedResults(ranked)
	if ranked[0].Name != "afast" {
		t.Fatalf("report must rank by speed, got %+v", ranked)
	}
	if inputOrder[0].Name != "zslow" {
		t.Fatalf("input order must be untouched, got %+v", inputOrder)
	}
}

func TestHostPortOf(t *testing.T) {
	if got := hostPortOf("vless://u@1.2.3.4:443?x=1#n"); got != "1.2.3.4:443" {
		t.Fatalf("got %q", got)
	}
	if got := hostPortOf("vmess://eyJhZGQiOiI1LjYuNy44IiwicG9ydCI6ODg4OH0="); got != "5.6.7.8:8888" {
		t.Fatalf("vmess got %q", got)
	}
}
