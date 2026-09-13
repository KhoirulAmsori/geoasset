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
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/constant"
	"golang.org/x/sync/errgroup"
)

var cfg Config

func main() {
	cfg = DefaultConfig()

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

	entries := parseToEntries(src, resolver)
	logPrintf("parsed %d reachable proxies", len(entries))

	entries = filterCountries(entries)
	if len(entries) == 0 {
		return fmt.Errorf("no proxy remains after country filter")
	}
	logPrintf("after country filter: %d", len(entries))

	ok := testAll(entries)
	ok = reindex(ok)
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
	if err := writeProxyList("all_list.txt", ok, true); err != nil {
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

func isInlineProxyLine(line string) bool {
	lower := strings.ToLower(line)
	for _, prefix := range []string{
		"vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "hy2://",
		"hysteria://", "tuic://", "wireguard://", "anytls://", "ssr://", "socks5://",
		"http://", "https://",
	} {
		if strings.HasPrefix(lower, prefix) {
			if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
				continue
			}
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
	return io.ReadAll(resp.Body)
}

func parseToEntries(raw []string, res *CountryResolver) []ProxyEntry {
	var out []ProxyEntry
	for _, line := range raw {
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
			URL:          line,
			Scheme:       scheme,
			Address:      address,
			OriginalName: entryNameFromURL(u),
		}
		e.CountryInfo = res.Resolve(dedupeKey(scheme, address), address)
		out = append(out, e)
	}
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
	var expected utils.IntRanges[uint16]
	if parsed, err := utils.NewUnsignedRanges[uint16](cfg.ExpectedStatus); err == nil {
		expected = parsed
	}

	nctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	delay, err := proxy.URLTest(nctx, cfg.TestURL, expected)
	if err != nil {
		return false
	}
	return delay > 0
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
