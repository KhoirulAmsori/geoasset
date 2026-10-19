package mihomo

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Loyalsoldier/geoip/lib"
	"github.com/klauspost/compress/zstd"
	"go4.org/netipx"
)

const (
	typeMihomoMRSOut = "mihomoMRS"
	descMihomoMRSOut = "Convert data to mihomo MRS v1 ipcidr ruleset, one file per list"

	// behaviorIPCIDR adalah byte behavior di container MRSv1. Nilai lain
	// membuat rule-provider dengan behavior: ipcidr menolak berkasnya.
	behaviorIPCIDR = 1

	// ipcidrSetVersion mengikuti versi yang ditulis cidr.IpCidrSet.WriteBin.
	ipcidrSetVersion = 1
)

var mrsMagic = [4]byte{'M', 'R', 'S', 1}

func init() {
	lib.RegisterOutputConfigCreator(typeMihomoMRSOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return newMihomoMRSOut(action, data)
	})
	lib.RegisterOutputConverter(typeMihomoMRSOut, &mihomoMRSOut{
		Description: descMihomoMRSOut,
	})
}

func newMihomoMRSOut(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir  string     `json:"outputDir"`
		Want       []string   `json:"wantedList"`
		Exclude    []string   `json:"excludedList"`
		OnlyIPType lib.IPType `json:"onlyIPType"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, err
		}
	}

	if tmp.OutputDir == "" {
		tmp.OutputDir = filepath.Join("./", "output", "mihomo", "mrs")
	}

	return &mihomoMRSOut{
		Type:        typeMihomoMRSOut,
		Action:      action,
		Description: descMihomoMRSOut,
		OutputDir:   tmp.OutputDir,
		Want:        tmp.Want,
		Exclude:     tmp.Exclude,
		OnlyIPType:  tmp.OnlyIPType,
	}, nil
}

type mihomoMRSOut struct {
	Type        string
	Action      lib.Action
	Description string
	OutputDir   string
	Want        []string
	Exclude     []string
	OnlyIPType  lib.IPType
}

func (m *mihomoMRSOut) GetType() string        { return m.Type }
func (m *mihomoMRSOut) GetAction() lib.Action  { return m.Action }
func (m *mihomoMRSOut) GetDescription() string { return m.Description }

// Output menulis satu berkas <list>.mrs per list, berisi aturan IP-CIDR
// (behavior ipcidr) untuk rule-providers mihomo dengan format: mrs.
func (m *mihomoMRSOut) Output(container lib.Container) error {
	if err := os.MkdirAll(m.OutputDir, 0755); err != nil {
		return err
	}

	written := 0
	for _, name := range filterList(container, m.Want, m.Exclude) {
		entry, found := container.GetEntry(name)
		if !found {
			log.Printf("❌ entry %s not found\n", name)
			continue
		}

		prefixes, err := entryPrefixes(entry, m.OnlyIPType)
		if err != nil {
			return fmt.Errorf("❌ [type %s | action %s] %w", m.Type, m.Action, err)
		}

		ranges, err := mergedRanges(prefixes)
		if err != nil {
			return fmt.Errorf("❌ [type %s | action %s] entry %s: %w", m.Type, m.Action, name, err)
		}

		buf, err := encodeMRS(len(prefixes), ranges)
		if err != nil {
			return fmt.Errorf("❌ [type %s | action %s] entry %s: %w", m.Type, m.Action, name, err)
		}

		filename := strings.ToLower(name) + ".mrs"
		if err := os.WriteFile(filepath.Join(m.OutputDir, filename), buf, 0644); err != nil {
			return err
		}

		log.Printf("✅ [%s] %s --> %s", m.Type, filename, m.OutputDir)
		written++
	}

	if written == 0 {
		return fmt.Errorf("❌ [type %s | action %s] no list written", m.Type, m.Action)
	}

	return nil
}

// encodeMRS membungkus range menjadi container MRSv1: zstd frame berisi magic,
// byte behavior, jumlah rule, panjang extra (0), lalu IpCidrSet biner
// (versi, jumlah range, per range 16 byte from dan 16 byte to).
func encodeMRS(rules int, ranges []netipx.IPRange) ([]byte, error) {
	payload := make([]byte, 0, 9+32*len(ranges))
	payload = append(payload, ipcidrSetVersion)
	payload = appendInt64(payload, int64(len(ranges)))
	for _, r := range ranges {
		from, to := r.From().As16(), r.To().As16()
		payload = append(payload, from[:]...)
		payload = append(payload, to[:]...)
	}

	var buf bytes.Buffer
	writer, err := zstd.NewWriter(&buf)
	if err != nil {
		return nil, err
	}

	header := make([]byte, 0, 4+1+8+8)
	header = append(header, mrsMagic[:]...)
	header = append(header, behaviorIPCIDR)
	header = appendInt64(header, int64(rules))
	header = appendInt64(header, 0)

	if _, err := writer.Write(header); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if _, err := writer.Write(payload); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// appendInt64 menulis int64 big-endian, sama seperti binary.Write yang dipakai
// mihomo saat menulis container MRS.
func appendInt64(dst []byte, value int64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(value))
	return append(dst, raw[:]...)
}
