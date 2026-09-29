package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/constant"
)

type SpeedResult struct {
	Name        string `json:"name"`
	Country     string `json:"country,omitempty"`
	Protocol    string `json:"protocol"`
	Address     string `json:"address,omitempty"`
	LatencyMS   int64  `json:"latency_ms"`
	Bytes       int64  `json:"bytes"`
	BytesPerSec int64  `json:"bytes_per_sec"`
	Error       string `json:"error,omitempty"`
}

func runSpeedTest() error {
	if !cfg.SpeedTestEnabled {
		logPrintf("speed test disabled (SpeedTestEnabled=false), skipping")
		return nil
	}
	start := time.Now()

	entries, err := parsePrevList(cfg.SpeedTestInput)
	if err != nil {
		return fmt.Errorf("read speed test input: %w", err)
	}
	if cfg.SpeedTestMaxNodes > 0 && len(entries) > cfg.SpeedTestMaxNodes {
		entries = entries[:cfg.SpeedTestMaxNodes]
	}
	logPrintf("speed test: %d nodes from %s", len(entries), cfg.SpeedTestInput)

	results := measureAll(entries)
	sortSpeedResults(results)

	ok := 0
	for _, r := range results {
		if r.Error == "" {
			ok++
		}
	}
	logPrintf("speed test done: measured %d, ok %d, failed %d, time spent: %s",
		len(results), ok, len(results)-ok, durationStr(time.Since(start)))

	report := formatSpeedReport(results, cfg.SpeedTestURL)
	if err := osWriteFile(cfg.SpeedTestReportBase+".txt", []byte(report)); err != nil {
		return err
	}
	if err := writeSpeedJSON(cfg.SpeedTestReportBase+".json", results); err != nil {
		return err
	}
	logPrintf("wrote %s.txt and %s.json", cfg.SpeedTestReportBase, cfg.SpeedTestReportBase)
	return nil
}

func measureAll(entries []PrevEntry) []SpeedResult {
	workers := cfg.SpeedTestThreadCount
	if workers < 1 {
		workers = 1
	}
	if workers > len(entries) && len(entries) > 0 {
		workers = len(entries)
	}

	results := make([]SpeedResult, len(entries))
	jobs := make(chan int)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				e := entries[idx]
				results[idx] = SpeedResult{
					Name:     e.Name,
					Country:  e.CC,
					Protocol: normalizeScheme(schemeFromURL(e.URL)),
					Address:  hostPortOf(e.URL),
				}
				measureOne(e.URL, &results[idx])
				if results[idx].Error == "" {
					logPrintf("speed %s: %d ms, %s", results[idx].Name, results[idx].LatencyMS, humanSpeed(results[idx].BytesPerSec))
				} else {
					logPrintf("speed %s: failed (%s)", results[idx].Name, results[idx].Error)
				}
			}
		}()
	}

	for i := range entries {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

func measureOne(rawURL string, res *SpeedResult) {
	mapping, err := convert.ConvertsV2Ray([]byte(rawURL))
	if err != nil || len(mapping) == 0 {
		res.Error = "parse failed"
		return
	}

	for _, m := range mapping {
		p, err := adapter.ParseProxy(m, adapter.WithDialerForAPI(dialer.NewDialer(dialer.WithPreferIPv4())))
		if err != nil {
			continue
		}
		sample, err := downloadThrough(p)
		_ = p.Close()
		if err != nil {
			res.Error = shortErr(err)
			continue
		}
		res.LatencyMS = sample.latencyMS
		res.Bytes = sample.bytes
		res.BytesPerSec = sample.bytesPerSec
		res.Error = ""
		return
	}
	if res.Error == "" {
		res.Error = "parse failed"
	}
}

// speedSample is one node's measurement: time to first byte and the byte rate
// observed over the body-read window.
type speedSample struct {
	latencyMS   int64
	bytes       int64
	bytesPerSec int64
}

func bytesPerSecOf(n, ms int64) int64 {
	if n <= 0 || ms <= 0 {
		return 0
	}
	return n * 1000 / ms
}

// downloadThrough dials the probe URL through the proxy, issues a GET and reads
// the body until SpeedTestMaxBytes or SpeedTestTimeout is reached. Latency is
// the time to first byte; the byte rate is measured over the body-read window
// only, so a slow first byte does not inflate throughput.
func downloadThrough(p constant.Proxy) (speedSample, error) {
	var sample speedSample

	meta, err := speedProbeMetadata(cfg.SpeedTestURL)
	if err != nil {
		return sample, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.SpeedTestTimeout)
	defer cancel()

	cons, err := p.DialContext(ctx, &meta)
	if err != nil {
		return sample, fmt.Errorf("dial failed: %s", shortErr(err))
	}
	defer cons.Close()

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return cons, nil
		},
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
		// Skip TLS verification: free nodes frequently have mismatched certs,
		// mirroring the permissive checks used during the liveness pass.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.SpeedTestURL, nil)
	if err != nil {
		return sample, fmt.Errorf("request failed")
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return sample, fmt.Errorf("request failed: %s", shortErr(err))
	}
	defer resp.Body.Close()

	sample.latencyMS = time.Since(start).Milliseconds()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return sample, fmt.Errorf("status %d", resp.StatusCode)
	}

	limit := cfg.SpeedTestMaxBytes
	if limit <= 0 {
		limit = 1 << 62
	}
	bodyStart := time.Now()
	n, cerr := io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	bodyMS := time.Since(bodyStart).Milliseconds()
	sample.bytes = n

	if cerr != nil {
		// A mid-stream cut (stall, reset, or deadline) is not a clean result:
		// fail the node instead of ranking a truncated transfer.
		return sample, fmt.Errorf("read failed: %s", shortErr(cerr))
	}
	if n == 0 {
		return sample, fmt.Errorf("no data")
	}
	sample.bytesPerSec = bytesPerSecOf(n, bodyMS)
	return sample, nil
}

func speedProbeMetadata(rawURL string) (constant.Metadata, error) {
	var meta constant.Metadata
	u, err := url.Parse(rawURL)
	if err != nil {
		return meta, err
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return meta, fmt.Errorf("unsupported scheme %q", u.Scheme)
		}
	}
	if err := meta.SetRemoteAddress(net.JoinHostPort(u.Hostname(), port)); err != nil {
		return meta, err
	}
	return meta, nil
}

func hostPortOf(raw string) string {
	host, port := extractHostPort(schemeFromURL(raw), raw)
	if host == "" {
		return ""
	}
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func sortSpeedResults(results []SpeedResult) {
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		aOK, bOK := a.Error == "", b.Error == ""
		if aOK != bOK {
			return aOK
		}
		if aOK {
			if a.BytesPerSec != b.BytesPerSec {
				return a.BytesPerSec > b.BytesPerSec
			}
			if a.LatencyMS != b.LatencyMS {
				return a.LatencyMS < b.LatencyMS
			}
		}
		return a.Name < b.Name
	})
}

func formatSpeedReport(results []SpeedResult, probeURL string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Speed test: %s (Asia/Jakarta)\n", jakartaTime())
	fmt.Fprintf(&sb, "# Test URL: %s\n", probeURL)

	ok := 0
	for _, r := range results {
		if r.Error == "" {
			ok++
		}
	}
	fmt.Fprintf(&sb, "# measured %d, ok %d, failed %d\n", len(results), ok, len(results)-ok)
	fmt.Fprintf(&sb, "# %-4s %-28s %-12s %9s %12s\n", "Rank", "Name", "Proto", "Latency", "Speed")

	rank := 0
	for _, r := range results {
		if r.Error != "" {
			continue
		}
		rank++
		fmt.Fprintf(&sb, "%-6d %-28s %-12s %9s %12s\n",
			rank, truncate(r.Name, 28), r.Protocol, humanLatency(r.LatencyMS), humanSpeed(r.BytesPerSec))
	}

	var failed []SpeedResult
	for _, r := range results {
		if r.Error != "" {
			failed = append(failed, r)
		}
	}
	if len(failed) > 0 {
		sb.WriteString("# failed\n")
		for _, r := range failed {
			fmt.Fprintf(&sb, "- %-28s %-12s %s\n", truncate(r.Name, 28), r.Protocol, r.Error)
		}
	}
	return sb.String()
}

func writeSpeedJSON(path string, results []SpeedResult) error {
	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return osWriteFile(path, b)
}

func humanLatency(ms int64) string {
	if ms <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d ms", ms)
}

func humanSpeed(bytesPerSec int64) string {
	if bytesPerSec <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.2f MB/s", float64(bytesPerSec)/1_000_000)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Strip Go's http wrapper: `Get "https://...": real reason`.
	if strings.HasPrefix(msg, "Get ") {
		if i := strings.Index(msg, `": `); i != -1 {
			msg = msg[i+3:]
		}
	}
	msg = strings.TrimSpace(msg)
	if strings.Contains(msg, "context deadline exceeded") {
		return "timeout"
	}
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return msg
}
