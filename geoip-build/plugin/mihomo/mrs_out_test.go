package mihomo

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/Loyalsoldier/geoip/lib"
	"github.com/klauspost/compress/zstd"
	"go4.org/netipx"
)

// TestOutputMRS memeriksa container MRSv1 hasil writer: nama berkas huruf
// kecil, behavior ipcidr, jumlah range sesuai hasil penggabungan prefix yang
// bersebelahan, dan isi range-nya benar.
func TestOutputMRS(t *testing.T) {
	container := lib.NewContainer()

	merged := lib.NewEntry("MERGED")
	private := lib.NewEntry("private")
	for cidr, e := range map[string]*lib.Entry{
		"1.1.1.0/24": merged,
		"1.1.2.0/24": merged,
		"10.0.0.0/8": private,
	} {
		if err := e.AddPrefix(cidr); err != nil {
			t.Fatalf("AddPrefix(%s): %v", cidr, err)
		}
	}
	for _, e := range []*lib.Entry{merged, private} {
		if err := container.Add(e); err != nil {
			t.Fatalf("container.Add(%s): %v", e.GetName(), err)
		}
	}

	dir := t.TempDir()
	converter, err := newMihomoMRSOut(lib.ActionOutput, json.RawMessage(fmt.Sprintf(`{"outputDir": %q}`, dir)))
	if err != nil {
		t.Fatalf("newMihomoMRSOut: %v", err)
	}
	if err := converter.Output(container); err != nil {
		t.Fatalf("Output: %v", err)
	}

	cases := []struct {
		file   string
		rules  int64
		ranges []netipx.IPRange
	}{
		{"merged.mrs", 2, []netipx.IPRange{
			ipRange("1.1.1.0", "1.1.2.255"), // dua /24 bersebelahan jadi satu range
		}},
		{"private.mrs", 1, []netipx.IPRange{
			ipRange("10.0.0.0", "10.255.255.255"),
		}},
	}

	for _, c := range cases {
		behavior, rules, ranges := decodeMRS(t, filepath.Join(dir, c.file))
		if behavior != behaviorIPCIDR {
			t.Errorf("%s: behavior = %d, ingin %d", c.file, behavior, behaviorIPCIDR)
		}
		if rules != c.rules {
			t.Errorf("%s: count = %d, ingin %d", c.file, rules, c.rules)
		}
		if len(ranges) != len(c.ranges) {
			t.Fatalf("%s: jumlah range = %d, ingin %d (%v)", c.file, len(ranges), len(c.ranges), ranges)
		}
		for i := range ranges {
			if ranges[i] != c.ranges[i] {
				t.Errorf("%s: range[%d] = %v, ingin %v", c.file, i, ranges[i], c.ranges[i])
			}
		}
	}
}

// decodeMRS membaca ulang container MRSv1, mengikuti urutan field pada
// rules/provider/mrs_reader.go: magic, behavior, count, extra, payload.
func decodeMRS(t *testing.T, path string) (behavior byte, rules int64, ranges []netipx.IPRange) {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("baca %s: %v", path, err)
	}

	reader, err := zstd.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("zstd %s: %v", path, err)
	}
	defer reader.Close()

	head := make([]byte, 4+1+8+8)
	if _, err := io.ReadFull(reader, head); err != nil {
		t.Fatalf("baca header %s: %v", path, err)
	}
	if string(head[:4]) != "MRS\x01" {
		t.Errorf("%s: magic = %q, ingin \"MRS\\x01\"", path, head[:4])
	}
	behavior = head[4]
	rules = int64(binary.BigEndian.Uint64(head[5:13]))
	if extraLen := int64(binary.BigEndian.Uint64(head[13:21])); extraLen != 0 {
		t.Fatalf("%s: extraLen = %d, ingin 0", path, extraLen)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("baca payload %s: %v", path, err)
	}

	if len(payload) < 9 {
		t.Fatalf("%s: payload pendek, %d byte", path, len(payload))
	}
	if payload[0] != ipcidrSetVersion {
		t.Errorf("%s: versi IpCidrSet = %d, ingin %d", path, payload[0], ipcidrSetVersion)
	}

	count := int(binary.BigEndian.Uint64(payload[1:9]))
	if got := (len(payload) - 9) / 32; got != count {
		t.Fatalf("%s: range_count = %d, isi payload cukup untuk %d range", path, count, got)
	}

	body := payload[9:]
	ranges = make([]netipx.IPRange, 0, count)
	for i := 0; i < count; i++ {
		from, ok := netip.AddrFromSlice(body[i*32 : i*32+16])
		if !ok {
			t.Fatalf("%s: range %d from tidak bisa dibaca", path, i)
		}
		to, ok := netip.AddrFromSlice(body[i*32+16 : i*32+32])
		if !ok {
			t.Fatalf("%s: range %d to tidak bisa dibaca", path, i)
		}
		ranges = append(ranges, netipx.IPRangeFrom(from.Unmap(), to.Unmap()))
	}

	return behavior, rules, ranges
}

// ipRange membuka jalan singkat untuk menulis range harapan di tabel test.
func ipRange(from, to string) netipx.IPRange {
	return netipx.IPRangeFrom(netip.MustParseAddr(from), netip.MustParseAddr(to))
}
