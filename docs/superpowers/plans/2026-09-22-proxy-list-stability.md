# Stabilitas `list.txt` antar-run (Carry-Forward) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mempertahankan baris `list.txt` lama (URL + nama) selama node-nya masih hidup, termasuk node "yatim" yang sudah tidak ada di sumber, sehingga isi `list.txt` stabil antar-run.

**Architecture:** Pipeline baru membaca `list.txt` run sebelumnya sebagai state, menyusun himpunan uji = kandidat hari ini ∪ URL lama, menguji semuanya, lalu merakit output lewat fungsi murni `mergeOutput(prev, candidates, alive)`. Identitas node = `scheme|host|port`. Perakitan output sepenuhnya deterministik dan dapat diuji offline tanpa jaringan.

**Tech Stack:** Go 1.27, `github.com/metacubex/mihomo` (tes node), `github.com/oschwald/geoip2-golang`. Tanpa dependensi baru.

**Spec:** `docs/superpowers/specs/2026-09-22-proxy-list-stability-design.md`

## Global Constraints

- Go 1.27; **tanpa dependensi baru**.
- Unit test harus **offline, tanpa jaringan** (tidak memanggil `URLTest`/DNS).
- `MaxThreadCount` tetap 512; tidak mengubah kebijakan tes (retry/timeout/status) selain yang sudah ada.
- Output harus deterministik: input sama → `list.txt` byte-identik.
- Semua perintah dijalankan dari direktori `proxy-build/`.
- Ikuti gaya kode yang ada: fungsi kecil, `logPrintf` untuk log, tanpa komentar kecuali perlu.

## Review Focus

Input/kondisi yang mudah menggigit dan tidak dicakup tes alur utama; tiap baris punya tes di task pemiliknya:

1. **`port` vmess bertipe JSON number (`443`) vs string (`"443"`)** — dua-duanya harus menghasilkan identitas `...|443`. (Task 1)
2. **Varian URL `ss://`** (SIP002 `...@host:port` maupun legacy base64) — host+port harus terekstrak. (Task 1)
3. **Baris `list.txt` lama dengan nama rusak / tanpa `CC N`** — harus dibawa apa adanya tanpa crash dan tanpa ikut penomoran. (Task 2, Task 3)
4. **Host IPv6 / port kosong** — tidak boleh salah gabung atau panic. (Task 1)
5. **URL kandidat yang tak dapat diparse** — dibuang, bukan digabung ke identitas kosong. (Task 1)

---

### Task 1: Identitas node + dedup berdasarkan identitas

**Files:**
- Modify: `proxy-build/pipeline.go`
- Modify: `proxy-build/main.go:59-60`
- Test: `proxy-build/pipeline_test.go` (baru)

**Interfaces:**
- Consumes: `ProxyEntry{Scheme, URL, Address, CountryInfo}` yang sudah ada.
- Produces:
  - `func extractHostPort(scheme, line string) (host, port string)`
  - `func identityKey(scheme, host, port string) string`
  - `func (e *ProxyEntry) Identity() string` — `""` bila host tak terbaca
  - `func dedupeByIdentity(entries []ProxyEntry) []ProxyEntry`
  - `func schemeFromURL(raw string) string`

- [ ] **Step 1: Tulis tes identitas yang gagal**

Buat `proxy-build/pipeline_test.go`:

```go
package main

import (
	"encoding/base64"
	"testing"
)

func vmessURL(t *testing.T, js string) string {
	t.Helper()
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
}

func TestIdentityVMessPortString(t *testing.T) {
	e := ProxyEntry{Scheme: "vmess", URL: vmessURL(t, `{"add":"1.2.3.4","port":"443","ps":"x"}`)}
	if got := e.Identity(); got != "vmess|1.2.3.4|443" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityVMessPortNumber(t *testing.T) {
	e := ProxyEntry{Scheme: "vmess", URL: vmessURL(t, `{"add":"1.2.3.4","port":443,"ps":"x"}`)}
	if got := e.Identity(); got != "vmess|1.2.3.4|443" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityVLESSLowercasesHost(t *testing.T) {
	e := ProxyEntry{Scheme: "vless", URL: "vless://uuid@Example.COM:8443?x=1#n"}
	if got := e.Identity(); got != "vless|example.com|8443" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentitySSSIP002(t *testing.T) {
	e := ProxyEntry{Scheme: "ss", URL: "ss://YWVzOnB3@1.2.3.4:8388#n"}
	if got := e.Identity(); got != "ss|1.2.3.4|8388" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentitySSLegacyBase64(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pass@5.6.7.8:443"))
	e := ProxyEntry{Scheme: "ss", URL: "ss://" + payload + "#n"}
	if got := e.Identity(); got != "ss|5.6.7.8|443" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityEmptyPort(t *testing.T) {
	e := ProxyEntry{Scheme: "trojan", URL: "trojan://p@host.com#n"}
	if got := e.Identity(); got != "trojan|host.com|" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityIPv6(t *testing.T) {
	e := ProxyEntry{Scheme: "vless", URL: "vless://u@[2001:db8::1]:443#n"}
	if got := e.Identity(); got != "vless|2001:db8::1|443" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityUnparseableIsEmpty(t *testing.T) {
	e := ProxyEntry{Scheme: "vless", URL: "not a url"}
	if got := e.Identity(); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestDedupeByIdentityDeterministic(t *testing.T) {
	a := ProxyEntry{Scheme: "vless", URL: "vless://u@1.2.3.4:443#b"}
	b := ProxyEntry{Scheme: "vless", URL: "vless://u@1.2.3.4:443#a"}
	got1 := dedupeByIdentity([]ProxyEntry{a, b})
	got2 := dedupeByIdentity([]ProxyEntry{b, a})
	if len(got1) != 1 || len(got2) != 1 {
		t.Fatalf("len %d %d", len(got1), len(got2))
	}
	if got1[0].URL != got2[0].URL || got1[0].URL != b.URL {
		t.Fatalf("nondeterministic: %q %q", got1[0].URL, got2[0].URL)
	}
}

func TestDedupeByIdentityDropsUnparseable(t *testing.T) {
	got := dedupeByIdentity([]ProxyEntry{{Scheme: "vless", URL: "garbage"}})
	if len(got) != 0 {
		t.Fatalf("expected drop, got %d", len(got))
	}
}
```

- [ ] **Step 2: Jalankan tes, pastikan gagal**

Run: `go test ./... -run 'Identity|Dedupe' -v`
Expected: FAIL — `undefined: dedupeByIdentity`, `e.Identity undefined`.

- [ ] **Step 3: Implementasi di `pipeline.go`**

Tambahkan `net` dan `strconv` pada blok import `pipeline.go` (import saat ini: `bufio`, `encoding/base64`, `encoding/json`, `fmt`, `net/url`, `sort`, `strings`, `time`), lalu tambahkan:

```go
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
```

Hapus fungsi `dedupeByIP` (pipeline.go:43-59) yang lama.

- [ ] **Step 4: Ubah call site di `main.go`**

Ganti (main.go:59-60):

```go
	entries = dedupeByIP(entries)
	logPrintf("after dedup by ip+scheme: %d", len(entries))
```

menjadi:

```go
	entries = dedupeByIdentity(entries)
	logPrintf("after dedup by identity: %d", len(entries))
```

- [ ] **Step 5: Jalankan tes, pastikan lulus**

Run: `go test ./... -run 'Identity|Dedupe' -v`
Expected: PASS.

- [ ] **Step 6: gofmt + vet + build**

Run: `gofmt -l . && go vet ./... && go build -o /tmp/nodechecker .`
Expected: tidak ada output dari gofmt, vet/build sukses.

- [ ] **Step 7: Commit**

```bash
git add proxy-build/pipeline.go proxy-build/main.go proxy-build/pipeline_test.go
git commit -m "feat(proxy-build): identitas node scheme|host|port + dedup by identity"
```

---

### Task 2: Parser `list.txt` lama → `PrevEntry`

**Files:**
- Modify: `proxy-build/pipeline.go`
- Test: `proxy-build/pipeline_test.go`

**Interfaces:**
- Consumes: `extractHostPort`, `identityKey` (Task 1); `os`, `bufio`, `url`, `strings`, `strconv`, `encoding/json`, `encoding/base64`.
- Produces:
  - `type PrevEntry struct { Identity, URL, Name, CC string }`
  - `func nameParts(name string) (cc string, num int, ok bool)`
  - `func parsePrevList(path string) ([]PrevEntry, error)`

- [ ] **Step 1: Tulis tes parser yang gagal**

Tambahkan ke `proxy-build/pipeline_test.go` (gabungkan ke blok import yang sudah ada dari Task 1 — tambahkan `os` dan `path/filepath`):

```go
func TestNameParts(t *testing.T) {
	cc, num, ok := nameParts("US 12 - Foo Bar")
	if !ok || cc != "US" || num != 12 {
		t.Fatalf("got %q %d %v", cc, num, ok)
	}
	if _, _, ok := nameParts("US - Foo"); ok {
		t.Fatal("malformed name should not parse")
	}
	if _, _, ok := nameParts(""); ok {
		t.Fatal("empty name should not parse")
	}
}

func TestParsePrevList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	vm := vmessURL(t, `{"add":"1.2.3.4","port":"443","ps":"US 1 - Foo"}`)
	content := "# Build date: x\n" +
		"vless://u@5.6.7.8:8443#DE 3 - Bar\n" +
		vm + "\n" +
		"garbage-line\n" +
		"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := parsePrevList(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].Identity != "vless|5.6.7.8|8443" || got[0].Name != "DE 3 - Bar" || got[0].CC != "DE" {
		t.Fatalf("bad first: %+v", got[0])
	}
	if got[1].Identity != "vmess|1.2.3.4|443" || got[1].Name != "US 1 - Foo" || got[1].CC != "US" {
		t.Fatalf("bad second: %+v", got[1])
	}
}

func TestParsePrevListMissingFile(t *testing.T) {
	got, err := parsePrevList(filepath.Join(t.TempDir(), "nope.txt"))
	if err != nil || got != nil {
		t.Fatalf("expected nil,nil got %v,%v", got, err)
	}
}
```

- [ ] **Step 2: Jalankan tes, pastikan gagal**

Run: `go test ./... -run 'NameParts|ParsePrevList' -v`
Expected: FAIL — `undefined: nameParts`, `undefined: parsePrevList`.

- [ ] **Step 3: Implementasi di `pipeline.go`**

```go
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
```

- [ ] **Step 4: Jalankan tes, pastikan lulus**

Run: `go test ./... -run 'NameParts|ParsePrevList' -v`
Expected: PASS.

- [ ] **Step 5: gofmt + vet**

Run: `gofmt -l . && go vet ./...`
Expected: bersih.

- [ ] **Step 6: Commit**

```bash
git add proxy-build/pipeline.go proxy-build/pipeline_test.go
git commit -m "feat(proxy-build): parser list.txt lama menjadi PrevEntry"
```

---

### Task 3: `buildTestSet` + `mergeOutput` (fungsi murni)

**Files:**
- Modify: `proxy-build/pipeline.go`
- Test: `proxy-build/pipeline_test.go`

**Interfaces:**
- Consumes: `PrevEntry`, `nameParts`, `ProxyEntry.Identity()`, `NormalizeISP`, `setName`.
- Produces:
  - `func buildTestSet(candidates []ProxyEntry, prev []PrevEntry) []ProxyEntry`
  - `func mergeOutput(prev []PrevEntry, candidates []ProxyEntry, alive map[string]bool) []ProxyEntry`

- [ ] **Step 1: Tulis tes merge yang gagal**

Tambahkan ke `proxy-build/pipeline_test.go`:

```go
func TestBuildTestSetDedup(t *testing.T) {
	cand := []ProxyEntry{{Scheme: "vless", URL: "vless://u@1.2.3.4:443"}}
	prevDiff := []PrevEntry{{Identity: "vless|1.2.3.4|443", URL: "vless://old@1.2.3.4:443"}}
	if got := buildTestSet(cand, prevDiff); len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	prevSame := []PrevEntry{{Identity: "vless|1.2.3.4|443", URL: "vless://u@1.2.3.4:443"}}
	if got := buildTestSet(cand, prevSame); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
}

func TestMergeCarryForwardOldAlive(t *testing.T) {
	p := PrevEntry{Identity: "vless|1.2.3.4|443", URL: "vless://u@1.2.3.4:443#US 1 - Foo", Name: "US 1 - Foo", CC: "US"}
	got := mergeOutput([]PrevEntry{p}, nil, map[string]bool{p.URL: true})
	if len(got) != 1 || got[0].URL != p.URL {
		t.Fatalf("got %+v", got)
	}
}

func TestMergeRotatedCredentialKeepsName(t *testing.T) {
	p := PrevEntry{Identity: "vless|1.2.3.4|443", URL: "vless://old@1.2.3.4:443#US 1 - Foo", Name: "US 1 - Foo", CC: "US"}
	c := ProxyEntry{Scheme: "vless", URL: "vless://new@1.2.3.4:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Foo"}}
	got := mergeOutput([]PrevEntry{p}, []ProxyEntry{c}, map[string]bool{c.URL: true})
	if len(got) != 1 || got[0].URL != "vless://new@1.2.3.4:443#US 1 - Foo" {
		t.Fatalf("got %+v", got)
	}
}

func TestMergeOrphanDeadDropped(t *testing.T) {
	p := PrevEntry{Identity: "vless|1.2.3.4|443", URL: "vless://u@1.2.3.4:443#US 1 - Foo", Name: "US 1 - Foo", CC: "US"}
	got := mergeOutput([]PrevEntry{p}, nil, map[string]bool{})
	if len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestMergeMalformedNameCarriedAsIs(t *testing.T) {
	p := PrevEntry{Identity: "vless|1.2.3.4|443", URL: "vless://u@1.2.3.4:443#weird", Name: "weird", CC: ""}
	got := mergeOutput([]PrevEntry{p}, nil, map[string]bool{p.URL: true})
	if len(got) != 1 || got[0].URL != p.URL {
		t.Fatalf("got %+v", got)
	}
}

func TestMergeNumberReuseSmallestFree(t *testing.T) {
	p := PrevEntry{Identity: "vless|9.9.9.9|443", URL: "vless://u@9.9.9.9:443#US 2 - B", Name: "US 2 - B", CC: "US"}
	c := ProxyEntry{Scheme: "vless", URL: "vless://u@1.1.1.1:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Foo"}}
	got := mergeOutput([]PrevEntry{p}, []ProxyEntry{c}, map[string]bool{p.URL: true, c.URL: true})
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].URL != "vless://u@1.1.1.1:443#US 1 - Foo" {
		t.Fatalf("new node not numbered 1: %q", got[0].URL)
	}
	if got[1].URL != p.URL {
		t.Fatalf("carried not preserved: %q", got[1].URL)
	}
}

func TestMergeNoPrevNumbersSequentially(t *testing.T) {
	c1 := ProxyEntry{Scheme: "vless", URL: "vless://a@1.1.1.1:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Foo"}}
	c2 := ProxyEntry{Scheme: "vless", URL: "vless://b@2.2.2.2:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Bar"}}
	alive := map[string]bool{c1.URL: true, c2.URL: true}
	got := mergeOutput(nil, []ProxyEntry{c1, c2}, alive)
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].URL != "vless://a@1.1.1.1:443#US 1 - Foo" || got[1].URL != "vless://b@2.2.2.2:443#US 2 - Bar" {
		t.Fatalf("got %q %q", got[0].URL, got[1].URL)
	}
}

func TestMergeDeterministic(t *testing.T) {
	c1 := ProxyEntry{Scheme: "vless", URL: "vless://a@1.1.1.1:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Foo"}}
	c2 := ProxyEntry{Scheme: "vless", URL: "vless://b@2.2.2.2:443", CountryInfo: CountryInfo{CountryCode: "US", Isp: "Bar"}}
	alive := map[string]bool{c1.URL: true, c2.URL: true}
	g1 := mergeOutput(nil, []ProxyEntry{c1, c2}, alive)
	g2 := mergeOutput(nil, []ProxyEntry{c2, c1}, alive)
	if len(g1) != len(g2) {
		t.Fatal("length differs")
	}
	for i := range g1 {
		if g1[i].URL != g2[i].URL {
			t.Fatalf("nondeterministic at %d: %q vs %q", i, g1[i].URL, g2[i].URL)
		}
	}
}
```

- [ ] **Step 2: Jalankan tes, pastikan gagal**

Run: `go test ./... -run 'BuildTestSet|Merge' -v`
Expected: FAIL — `undefined: buildTestSet`, `undefined: mergeOutput`.

- [ ] **Step 3: Implementasi di `pipeline.go`**

```go
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
```

- [ ] **Step 4: Jalankan tes, pastikan lulus**

Run: `go test ./... -run 'BuildTestSet|Merge' -v`
Expected: PASS.

- [ ] **Step 5: gofmt + vet**

Run: `gofmt -l . && go vet ./...`
Expected: bersih.

- [ ] **Step 6: Commit**

```bash
git add proxy-build/pipeline.go proxy-build/pipeline_test.go
git commit -m "feat(proxy-build): buildTestSet + mergeOutput murni deterministik"
```

---

### Task 4: Wiring pipeline + env `PreviousListFile`

**Files:**
- Modify: `proxy-build/config.go`
- Modify: `proxy-build/main.go`
- Test: `proxy-build/pipeline_test.go` (tes `mergeOutput` sudah ada)

**Interfaces:**
- Consumes: `parsePrevList`, `buildTestSet`, `mergeOutput`, `dedupeByIdentity`, `testAll`.
- Produces: alur `run()` baru; `Config.PreviousListFile`.

- [ ] **Step 1: Tambah env di `config.go`**

Pada struct `Config`, tambahkan field:

```go
	PreviousListFile     string
```

Pada `DefaultConfig()`, tambahkan di dalam literal:

```go
		PreviousListFile:     envOr("PreviousListFile", ""),
```

- [ ] **Step 2: Ubah `run()` di `main.go`**

Ganti blok dari baris `entries := parseToEntriesParallel(...)` sampai sebelum `if cfg.MaxProxiesPerCountry > 0`:

```go
	entries := parseToEntriesParallel(src, resolver)
	logPrintf("parsed %d reachable proxies", len(entries))

	entries = dedupeByIdentity(entries)
	logPrintf("after dedup by identity: %d", len(entries))

	prev, err := parsePrevList(cfg.PreviousListFile)
	if err != nil {
		return fmt.Errorf("read previous list: %w", err)
	}
	logPrintf("previous list entries: %d", len(prev))

	entries = filterCountries(entries)
	if len(entries) == 0 && len(prev) == 0 {
		return fmt.Errorf("no proxy remains after country filter")
	}
	logPrintf("after country filter: %d", len(entries))

	testSet := buildTestSet(entries, prev)
	logPrintf("testing %d urls", len(testSet))
	passed := testAll(testSet)

	aliveURLs := make(map[string]bool, len(passed))
	for _, p := range passed {
		aliveURLs[p.URL] = true
	}

	ok := mergeOutput(prev, entries, aliveURLs)
```

Kemudian hapus baris `ok = reindex(ok)` (yang lama) dan hapus fungsi `reindex` di `pipeline.go` karena sudah digantikan `mergeOutput`.

- [ ] **Step 3: Build + vet**

Run: `go build -o /tmp/nodechecker . && go vet ./...`
Expected: sukses.

- [ ] **Step 4: Tes unit penuh**

Run: `go test ./...`
Expected: PASS (semua tes Task 1-3).

- [ ] **Step 5: Verifikasi manual tanpa carry-forward (perilaku lama)**

Run: `PreviousListFile= go run . 2>&1 | tail -6`
Expected: log berisi `previous list entries: 0`, `active proxies: <n>`, dan `list.txt` terisi. (Butuh akses jaringan; bila offline, lewati langkah ini dan catat.)

- [ ] **Step 6: Verifikasi manual carry-forward (dua run berurutan)**

Run:
```bash
PreviousListFile= go run .
cp list.txt /tmp/list_run1.txt
PreviousListFile=list.txt go run .
diff <(grep -v '^#' /tmp/list_run1.txt) <(grep -v '^#' list.txt) | head
```
Expected: log `previous list entries: <n>` > 0; diff didominasi penambahan/penghapusan minor, baris yang masih hidup tetap identik. (Butuh jaringan.)

- [ ] **Step 7: gofmt + commit**

Run: `gofmt -l .`
Expected: bersih.

```bash
git add proxy-build/config.go proxy-build/main.go proxy-build/pipeline.go
git commit -m "feat(proxy-build): wiring carry-forward dari list.txt sebelumnya"
```

---

### Task 5: Env workflow GitHub Actions

**Files:**
- Modify: `.github/workflows/build_proxy.yml`

**Interfaces:**
- Consumes: env `PreviousListFile` (Task 4).
- Produces: job CI memakai `GEO/Proxy/list.txt` sebagai state.

- [ ] **Step 1: Tambahkan env**

Pada blok `env:` job `Build` (setelah `SourcesFile: Asset/sources.txt`), tambahkan:

```yaml
      PreviousListFile: GEO/Proxy/list.txt
```

- [ ] **Step 2: Verifikasi YAML**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/build_proxy.yml')); print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/build_proxy.yml
git commit -m "ci(proxy): pakai list.txt sebelumnya sebagai state carry-forward"
```

---

## Catatan Verifikasi Akhir (untuk pengguna)

Setelah rilis, jalankan dua kali di CI:
1. Run pertama: `list.txt` terisi seperti biasa; log `previous list entries: 0` (atau jumlah dari run sebelumnya).
2. Run kedua: sebagian besar baris identik; log `previous list entries: <n>` > 0.

Metrik: jumlah baris `list.txt` dan jumlah baris yang berubah antar dua run.

---

## Errata (setelah review)

- **Task 3 renumber guard:** plan menyebut `chosen[i].hasNum`, implementasi memakai
  `chosen[i].name != ""`. Ini disengaja: spec §2 ("URL baru, pertahankan nama lama")
  mengharuskan nama lama dipertahankan apa adanya, termasuk nama yang tidak
  terparse. `hasNum` akan menimpa nama lama yang malformed dengan
  `<cc> N - Unknown`. Jangan "koreksi" kembali ke `hasNum`.
- **Task 4 filter negara:** baris lama juga melewati filter negara yang sama
  dengan kandidat (fungsi bersama `countryAllowed`), termasuk membuang CC kosong/`ZZ`.
- **Parser `%`:** `parsePrevLine` tidak memakai `url.Parse` sebagai gerbang
  validitas, dan `extractAddress`/`parseProxyURL` memotong fragment `#` sebelum
  `url.Parse`, agar nama ber-`%` literal (output program sendiri) bisa dibaca kembali.
