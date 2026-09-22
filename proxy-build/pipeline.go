package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ProxyEntry struct {
	URL         string
	Scheme      string
	Address     string
	CountryInfo CountryInfo
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

func schemeFromURL(raw string) string {
	if i := strings.Index(raw, "://"); i != -1 {
		return raw[:i]
	}
	return ""
}

func identityKey(scheme, host, port string) string {
	return strings.ToLower(scheme) + "|" + strings.ToLower(host) + "|" + strings.ToLower(port)
}

func extractHostPort(scheme, line string) (string, string) {
	switch strings.ToLower(scheme) {
	case "vmess":
		payload := strings.TrimPrefix(line, "vmess://")
		b, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(payload)
		}
		if err != nil {
			return "", ""
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return "", ""
		}
		host, _ := m["add"].(string)
		port := ""
		switch v := m["port"].(type) {
		case string:
			port = v
		case float64:
			port = strconv.Itoa(int(v))
		}
		return host, port
	case "ss":
		return ssHostPort(line)
	default:
		u, err := url.Parse(line)
		if err != nil {
			return "", ""
		}
		return u.Hostname(), u.Port()
	}
}

func ssHostPort(line string) (string, string) {
	payload := line
	if i := strings.IndexAny(payload, "?#"); i != -1 {
		payload = payload[:i]
	}
	payload = strings.TrimPrefix(payload, "ss://")

	split := func(hostport string) (string, string) {
		if i := strings.IndexAny(hostport, "/#?"); i != -1 {
			hostport = hostport[:i]
		}
		if h, p, err := net.SplitHostPort(hostport); err == nil {
			return h, p
		}
		return hostport, ""
	}

	if strings.Contains(payload, "@") {
		return split(strings.SplitN(payload, "@", 2)[1])
	}
	if b, err := base64.StdEncoding.DecodeString(payload); err == nil {
		decoded := string(b)
		if at := strings.IndexByte(decoded, '@'); at != -1 {
			return split(decoded[at+1:])
		}
	}
	return "", ""
}

func (e *ProxyEntry) Identity() string {
	host, port := extractHostPort(e.Scheme, e.URL)
	if host == "" {
		return ""
	}
	return identityKey(e.Scheme, host, port)
}

func dedupeByIdentity(entries []ProxyEntry) []ProxyEntry {
	sorted := make([]ProxyEntry, len(entries))
	copy(sorted, entries)
	sort.SliceStable(sorted, func(i, j int) bool {
		ii, ij := sorted[i].Identity(), sorted[j].Identity()
		if ii != ij {
			return ii < ij
		}
		return sorted[i].URL < sorted[j].URL
	})
	seen := map[string]bool{}
	var out []ProxyEntry
	for _, e := range sorted {
		id := e.Identity()
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, e)
	}
	return out
}

type PrevEntry struct {
	Identity string
	URL      string
	Name     string
	CC       string
}

func nameParts(name string) (string, int, bool) {
	left := name
	if i := strings.Index(name, " - "); i != -1 {
		left = name[:i]
	}
	fields := strings.Fields(left)
	if len(fields) != 2 {
		return "", 0, false
	}
	n, err := strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, false
	}
	return fields[0], n, true
}

func vmessName(line string) string {
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
	name, _ := m["ps"].(string)
	return name
}

func parsePrevLine(line string) (PrevEntry, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return PrevEntry{}, false
	}
	u, err := url.Parse(line)
	if err != nil || u.Scheme == "" {
		return PrevEntry{}, false
	}
	scheme := strings.ToLower(u.Scheme)
	host, port := extractHostPort(scheme, line)
	if host == "" {
		return PrevEntry{}, false
	}
	name := ""
	if scheme == "vmess" {
		name = vmessName(line)
	} else if u.Fragment != "" {
		if dec, err := url.PathUnescape(u.Fragment); err == nil {
			name = dec
		} else {
			name = u.Fragment
		}
	}
	cc, _, _ := nameParts(name)
	return PrevEntry{
		Identity: identityKey(scheme, host, port),
		URL:      line,
		Name:     name,
		CC:       cc,
	}, true
}

func parsePrevList(path string) ([]PrevEntry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			logPrintf("previous list %s not found, skipping carry-forward", path)
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var out []PrevEntry
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		e, ok := parsePrevLine(sc.Text())
		if !ok {
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func buildTestSet(candidates []ProxyEntry, prev []PrevEntry) []ProxyEntry {
	seen := map[string]bool{}
	var out []ProxyEntry
	for _, c := range candidates {
		id := c.Identity()
		if id == "" {
			continue
		}
		key := id + "|" + c.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ProxyEntry{URL: c.URL})
	}
	for _, p := range prev {
		key := p.Identity + "|" + p.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ProxyEntry{URL: p.URL})
	}
	return out
}

type mergedEntry struct {
	url      string
	name     string
	cc       string
	num      int
	hasNum   bool
	needsSet bool
	isp      string
}

func mergeOutput(prev []PrevEntry, candidates []ProxyEntry, alive map[string]bool) []ProxyEntry {
	prevByIdentity := map[string][]PrevEntry{}
	for _, p := range prev {
		prevByIdentity[p.Identity] = append(prevByIdentity[p.Identity], p)
	}
	for id := range prevByIdentity {
		ps := prevByIdentity[id]
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].URL < ps[j].URL })
	}

	candByIdentity := map[string][]ProxyEntry{}
	for _, c := range candidates {
		id := c.Identity()
		if id == "" {
			continue
		}
		candByIdentity[id] = append(candByIdentity[id], c)
	}
	for id := range candByIdentity {
		cs := candByIdentity[id]
		sort.SliceStable(cs, func(i, j int) bool { return cs[i].URL < cs[j].URL })
	}

	idSet := map[string]bool{}
	for id := range prevByIdentity {
		idSet[id] = true
	}
	for id := range candByIdentity {
		idSet[id] = true
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var chosen []mergedEntry
	for _, id := range ids {
		prevs := prevByIdentity[id]

		picked := false
		for _, p := range prevs {
			if alive[p.URL] {
				cc, num, ok := nameParts(p.Name)
				chosen = append(chosen, mergedEntry{url: p.URL, name: p.Name, cc: cc, num: num, hasNum: ok})
				picked = true
				break
			}
		}
		if picked {
			continue
		}

		for _, c := range candByIdentity[id] {
			if !alive[c.URL] {
				continue
			}
			m := mergedEntry{url: c.URL, needsSet: true}
			if len(prevs) > 0 {
				m.name = prevs[0].Name
				cc, num, ok := nameParts(m.name)
				m.cc, m.num, m.hasNum = cc, num, ok
			} else {
				m.cc = c.CountryInfo.CountryCode
				m.isp = c.CountryInfo.Isp
			}
			chosen = append(chosen, m)
			break
		}
	}

	used := map[string]map[int]bool{}
	for _, m := range chosen {
		if m.hasNum {
			if used[m.cc] == nil {
				used[m.cc] = map[int]bool{}
			}
			used[m.cc][m.num] = true
		}
	}
	for i := range chosen {
		if !chosen[i].needsSet || chosen[i].name != "" {
			continue
		}
		if used[chosen[i].cc] == nil {
			used[chosen[i].cc] = map[int]bool{}
		}
		n := 1
		for used[chosen[i].cc][n] {
			n++
		}
		used[chosen[i].cc][n] = true
		chosen[i].num = n
		chosen[i].hasNum = true
		chosen[i].name = fmt.Sprintf("%s %d - %s", chosen[i].cc, n, NormalizeISP(chosen[i].isp))
	}

	sort.SliceStable(chosen, func(i, j int) bool {
		if chosen[i].cc != chosen[j].cc {
			return chosen[i].cc < chosen[j].cc
		}
		if chosen[i].num != chosen[j].num {
			return chosen[i].num < chosen[j].num
		}
		return chosen[i].url < chosen[j].url
	})

	out := make([]ProxyEntry, 0, len(chosen))
	for _, m := range chosen {
		e := ProxyEntry{URL: m.url}
		if m.needsSet {
			e.URL = setName(m.url, schemeFromURL(m.url), "", m.name)
		}
		e.CountryInfo.CountryCode = m.cc
		out = append(out, e)
	}
	return out
}

func limitPerCountry(entries []ProxyEntry, max int) []ProxyEntry {
	idx := map[string]int{}
	var out []ProxyEntry
	for _, e := range entries {
		cc := e.CountryInfo.CountryCode
		if idx[cc] >= max {
			continue
		}
		idx[cc]++
		out = append(out, e)
	}
	return out
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
