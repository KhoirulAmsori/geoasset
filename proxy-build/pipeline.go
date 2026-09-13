package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

type ProxyEntry struct {
	URL          string
	Scheme       string
	Address      string
	OriginalName string
	CountryInfo  CountryInfo
}

func parseSubContent(content []byte) ([]string, error) {
	text := string(content)
	if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text)); err == nil {
		text = string(b)
	}
	lines := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if _, ok := lines[line]; !ok {
			lines[line] = true
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func (e *ProxyEntry) Key() string {
	switch strings.ToLower(e.Scheme) {
	case "vmess":
		return "vmess|" + strings.ToLower(e.Address)
	case "ss", "vless", "trojan", "hysteria2", "hy2", "tuic", "hysteria", "wireguard", "anytls", "tailscale", "ssh", "socks5", "http", "ssr", "snell":
		return strings.ToLower(e.Scheme) + "|" + strings.ToLower(e.Address)
	default:
		return e.URL
	}
}

func entryNameFromURL(u *url.URL) string {
	if u.Fragment != "" {
		if dec, err := url.PathUnescape(u.Fragment); err == nil {
			u.Fragment = dec
		}
	}
	return u.Fragment
}

func extractAddress(scheme, line string) string {
	switch strings.ToLower(scheme) {
	case "vmess":
		payload := strings.TrimPrefix(line, "vmess://")
		b, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(payload)
		}
		if err != nil {
			return ""
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return ""
		}
		add, _ := m["add"].(string)
		return add
	case "ss":
		payload := line
		if i := strings.IndexAny(payload, "?#"); i != -1 {
			payload = payload[:i]
		}
		payload = strings.TrimPrefix(payload, "ss://")
		if strings.Contains(payload, "@") {
			host := strings.SplitN(payload, "@", 2)[1]
			if i := strings.IndexAny(host, "/#?"); i != -1 {
				host = host[:i]
			}
			if strings.Contains(host, ":") {
				return strings.SplitN(host, ":", 2)[0]
			}
			return host
		}
		if b, err := base64.StdEncoding.DecodeString(payload); err == nil {
			decoded := string(b)
			if at := strings.IndexByte(decoded, '@'); at != -1 {
				host := decoded[at+1:]
				if i := strings.IndexAny(host, "/#?"); i != -1 {
					host = host[:i]
				}
				if strings.Contains(host, ":") {
					return strings.SplitN(host, ":", 2)[0]
				}
				return host
			}
		}
		return ""
	default:
		u, err := url.Parse(line)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
}

var formalSuffixes = map[string]bool{
	"SAS": true, "INC": true, "LTD": true, "LLC": true, "CORP": true,
	"CO": true, "SA": true, "SRO": true, "ASN": true, "LIMITED": true,
	"COMPANY": true, "ASIA": true, "CLOUD": true, "INTERNATIONAL": true,
	"PROVIDER": true, "ISLAND": true, "PRIVATE": true, "ONLINE": true,
	"OF": true, "AS": true, "BV": true, "HK": true, "PTE": true,
	"GMBH": true, "AG": true, "CMS": true, "PJSC": true, "AO": true,
	"LTD.": true, "INC.": true, "CORP.": true, "PHILS": true,
}

func NormalizeISP(isp string) string {
	if strings.TrimSpace(isp) == "" {
		return "Unknown"
	}
	raw := strings.NewReplacer(".", "", ",", "").Replace(strings.TrimSpace(isp))
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == '-'
	})
	var parts []string
	for _, f := range fields {
		if !formalSuffixes[strings.ToUpper(f)] {
			parts = append(parts, f)
		}
	}
	if len(parts) == 0 {
		return "Unknown"
	}
	if len(parts) > 2 {
		return strings.Join(parts[:2], " ")
	}
	return strings.Join(parts, " ")
}

func jakartaTime() string {
	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		return time.Now().Format("02-01-2006 15:04:05")
	}
	return time.Now().In(loc).Format("02-01-2006 15:04:05")
}

func writeList(path string, entries []ProxyEntry, withHeader bool) error {
	lines := make([]string, 0, len(entries)+1)
	if withHeader {
		lines = append(lines, "# Build date: "+jakartaTime())
	}
	for _, e := range entries {
		lines = append(lines, e.URL)
	}
	return writeLines(path, lines)
}

func writeLines(path string, lines []string) error {
	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	return osWriteFile(path, []byte(sb.String()))
}

func parseUint16(s string) (uint16, error) {
	var n uint16
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid")
		}
		n = n*10 + uint16(c-'0')
	}
	return n, nil
}

func dedupeSort(entries []ProxyEntry) []ProxyEntry {
	seen := map[string]*ProxyEntry{}
	var order []string
	for i := range entries {
		k := entries[i].Key()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = &entries[i]
		order = append(order, k)
	}
	out := make([]ProxyEntry, 0, len(order))
	for _, k := range order {
		out = append(out, *seen[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CountryInfo.CountryCode == out[j].CountryInfo.CountryCode {
			return out[i].Address < out[j].Address
		}
		return out[i].CountryInfo.CountryCode < out[j].CountryInfo.CountryCode
	})
	return out
}

func reindex(entries []ProxyEntry) []ProxyEntry {
	idx := map[string]int{}
	sort.SliceStable(entries, func(i, j int) bool {
		ci, cj := entries[i].CountryInfo.CountryCode, entries[j].CountryInfo.CountryCode
		if ci == cj {
			return entries[i].Address < entries[j].Address
		}
		return ci < cj
	})
	out := make([]ProxyEntry, 0, len(entries))
	for _, e := range entries {
		cc := e.CountryInfo.CountryCode
		if _, ok := idx[cc]; !ok {
			idx[cc] = 1
		}
		name := fmt.Sprintf("%s %d - %s", cc, idx[cc], NormalizeISP(e.CountryInfo.Isp))
		e.URL = setName(e.URL, e.Scheme, e.Address, name)
		idx[cc]++
		out = append(out, e)
	}
	return out
}

func setName(urlStr, scheme, address, name string) string {
	switch strings.ToLower(scheme) {
	case "vmess":
		return setVmessName(urlStr, name)
	case "ss":
		return setSSName(urlStr, name)
	default:
		return setURLEndPointName(urlStr, name)
	}
}

func setURLEndPointName(raw string, name string) string {
	idx := strings.IndexByte(raw, '#')
	if idx != -1 {
		return raw[:idx] + "#" + name
	}
	return raw + "#" + name
}

func setVmessName(raw, name string) string {
	payload := strings.TrimPrefix(raw, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return raw
	}
	var m map[string]any
	if json.Unmarshal(decoded, &m) != nil {
		return raw
	}
	m["ps"] = name
	b, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func setSSName(raw, name string) string {
	body := strings.TrimPrefix(raw, "ss://")
	if at := strings.IndexByte(body, '@'); at != -1 {
		hostPart := body[:at]
		rest := body[at+1:]
		hash := strings.IndexByte(rest, '#')
		if hash != -1 {
			return "ss://" + hostPart + "@" + rest[:hash] + "#" + name
		}
		return "ss://" + hostPart + "@" + rest + "#" + name
	}
	return raw
}

func (e *ProxyEntry) buildByMapping(m map[string]any) {
	display, _ := m["type"].(string)
	tp, _ := m["server"].(string)
	netStr, _ := m["name"].(string)
	e.Scheme = display
	e.Address = tp
	e.OriginalName = netStr
}
