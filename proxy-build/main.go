package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/constant"
	mihomoLog "github.com/metacubex/mihomo/log"
	"golang.org/x/sync/errgroup"
)

var cfg Config

const maxSourceBytes = 32 << 20

func main() {
	cfg = DefaultConfig()
	mihomoLog.SetLevel(mihomoLog.SILENT)

	if err := run(); err != nil {
		log.Fatalf("failed: %v", err)
	}
}

func run() error {
	start := time.Now()

	logPrintf("collector started")
	src, err := fetchSources(cfg.SourcesFile, cfg.MaxThreadCount)
	if err != nil {
		return err
	}
	logPrintf("fetched %d unique raw links", len(src))

	resolver, err := OpenCountryResolver(cfg.GeoIPCountryDB, cfg.GeoIPASNDB, cfg.ConcurrentDNS)
	if err != nil {
		return fmt.Errorf("open geoip db: %w", err)
	}
	defer resolver.Close()

	entries := parseToEntriesParallel(src, resolver)
	logPrintf("parsed %d reachable proxies", len(entries))

	entries = dedupeByIP(entries)
	logPrintf("after dedup by ip+scheme: %d", len(entries))

	entries = filterCountries(entries)
	if len(entries) == 0 {
		return fmt.Errorf("no proxy remains after country filter")
	}
	logPrintf("after country filter: %d", len(entries))

	ok := testAll(entries)
	ok = reindex(ok)

	if cfg.MaxProxiesPerCountry > 0 {
		ok = limitPerCountry(ok, cfg.MaxProxiesPerCountry)
	}

	logPrintf("active proxies: %d", len(ok))

	if len(ok) < cfg.MinActiveProxies {
		logPrintf("active (%d) less than required (%d), writing skip_push.flag", len(ok), cfg.MinActiveProxies)
		if err := osWriteFile("skip_push.flag", []byte("not enough proxies")); err != nil {
			return err
		}
		return nil
	}

	if err := writeProxyList("list.txt", ok, true); err != nil {
		return err
	}

	logPrintf("job finished, time spent: %s", durationStr(time.Since(start)))
	return nil
}

func fetchSources(path string, concurrency int) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var sources []string
	var inline []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if isInlineProxyLine(line) {
			inline = append(inline, line)
		} else {
			sources = append(sources, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 15 * time.Second}

	var mu sync.Mutex
	var all []string
	all = append(all, inline...)

	eg, _ := errgroup.WithContext(context.Background())
	eg.SetLimit(concurrency)

	for _, src := range sources {
		src := src
		eg.Go(func() error {
			body, err := fetchOne(client, src)
			if err != nil {
				logPrintf("failed to fetch %s: %v", src, err)
				return nil
			}
			lines, _ := parseSubContent(body)
			mu.Lock()
			all = append(all, lines...)
			mu.Unlock()
			logPrintf("got %d proxies from %s", len(lines), src)
			return nil
		})
	}
	eg.Wait()

	seen := map[string]bool{}
	out := all[:0]
	for _, l := range all {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out, nil
}

var inlineProxyPrefixes = []string{
	"vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "hy2://",
	"hysteria://", "tuic://", "wireguard://", "anytls://", "ssr://", "socks5://",
}

func isInlineProxyLine(line string) bool {
	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
		return false
	}
	lower := strings.ToLower(line)
	for _, prefix := range inlineProxyPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func fetchOne(client *http.Client, src string) ([]byte, error) {
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		return os.ReadFile(src)
	}
	req, err := http.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes))
}

func parseToEntriesParallel(raw []string, res *CountryResolver) []ProxyEntry {
	workers := cfg.MaxThreadCount
	if workers < 4 {
		workers = 4
	}
	if workers > 1024 {
		workers = 1024
	}

	var (
		out  []ProxyEntry
		lock sync.Mutex
		wg   sync.WaitGroup
		jobs = make(chan string)
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range jobs {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				u, err := url.Parse(line)
				if err != nil {
					continue
				}
				scheme := strings.ToLower(u.Scheme)
				if scheme == "" {
					continue
				}

				address := extractAddress(scheme, line)
				if address == "" {
					continue
				}

				if isPrivateAddress(address) {
					continue
				}

				e := ProxyEntry{
					URL:     line,
					Scheme:  scheme,
					Address: address,
				}
				e.CountryInfo = res.Resolve(dedupeKey(scheme, address), address)

				lock.Lock()
				out = append(out, e)
				lock.Unlock()
			}
		}()
	}

	for _, line := range raw {
		jobs <- line
	}
	close(jobs)
	wg.Wait()
	return out
}

func filterCountries(entries []ProxyEntry) []ProxyEntry {
	var out []ProxyEntry
	for _, e := range entries {
		cc := e.CountryInfo.CountryCode
		skip := false
		if cc == "" || cc == "ZZ" || cc == "Unknown" {
			skip = true
		} else if len(cfg.ExcludedCountries) > 0 && cfg.ExcludedCountries[cc] {
			skip = true
		} else if len(cfg.IncludedCountries) > 0 && !cfg.IncludedCountries[cc] {
			skip = true
		}
		if skip {
			continue
		}
		out = append(out, e)
	}
	return out
}

func testAll(entries []ProxyEntry) []ProxyEntry {
	const batch = 4000
	var passed []ProxyEntry
	for i := 0; i < len(entries); i += batch {
		end := i + batch
		if end > len(entries) {
			end = len(entries)
		}
		chunk := entries[i:end]
		ok := testBatch(chunk)
		passed = append(passed, ok...)
		logPrintf("tested %d/%d batch, passed %d", end, len(entries), len(ok))
	}
	return passed
}

func testBatch(entries []ProxyEntry) []ProxyEntry {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxies, sourceIdx := buildProxies(entries)

	var mu sync.Mutex
	passedSet := map[int]bool{}
	var passed []ProxyEntry
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.MaxThreadCount)

	for i, proxy := range proxies {
		origIdx := sourceIdx[i]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if testOne(ctx, proxy) {
				mu.Lock()
				if !passedSet[origIdx] {
					passedSet[origIdx] = true
					passed = append(passed, entries[origIdx])
				}
				mu.Unlock()
			}
			_ = proxy.Close()
		}()
	}
	wg.Wait()
	return passed
}

func buildProxies(entries []ProxyEntry) ([]constant.Proxy, []int) {
	var proxies []constant.Proxy
	var sourceIdx []int
	for i, entry := range entries {
		mapping, err := convert.ConvertsV2Ray([]byte(entry.URL))
		if err != nil || len(mapping) == 0 {
			continue
		}
		for _, m := range mapping {
			p, err := adapter.ParseProxy(m, adapter.WithDialerForAPI(dialer.NewDialer(dialer.WithPreferIPv4())))
			if err != nil {
				continue
			}
			proxies = append(proxies, p)
			sourceIdx = append(sourceIdx, i)
		}
	}
	return proxies, sourceIdx
}

func testOne(ctx context.Context, proxy constant.Proxy) bool {
	for attempt := 0; attempt <= cfg.RetryCount; attempt++ {
		nctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		delay, err := proxy.URLTest(nctx, cfg.TestURL, cfg.ExpectedRanges)
		cancel()
		if err == nil {
			return delay > 0
		}
		if ctx.Err() != nil {
			return false
		}
	}
	return false
}

func isPrivateAddress(address string) bool {
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() ||
		(ip.Is4() && ip.As4()[0] == 100 && ip.As4()[1] >= 64 && ip.As4()[1] <= 127)
}

func dedupeKey(scheme, address string) string {
	return strings.ToLower(scheme) + "|" + strings.ToLower(address)
}

func durationStr(d time.Duration) string {
	m := int(d.Minutes())
	s := d % time.Minute / time.Second
	return fmt.Sprintf("%02d minutes and %02d seconds", m, s)
}

func logPrintf(format string, args ...any) {
	log.Printf("%s - %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func osWriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

func writeProxyList(name string, entries []ProxyEntry, header bool) error {
	dir := filepath.Dir(name)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return writeList(name, entries, header)
}
