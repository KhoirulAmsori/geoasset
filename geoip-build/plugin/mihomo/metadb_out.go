package mihomo

import (
	"cmp"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Loyalsoldier/geoip/lib"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

const (
	typeMihomoMetaDBOut = "mihomoMetaDB"
	descMihomoMetaDBOut = "Convert data to the mihomo Meta-geoip0 mmdb format, one IP may answer multiple list names"

	// databaseTypeMeta harus persis sama dengan string yang di-switch pada
	// component/mmdb di mihomo. Nilai lain akan dianggap database MaxMind
	// (GeoLite2-Country) sehingga hanya country.iso_code yang dibaca.
	databaseTypeMeta = "Meta-geoip0"
)

var (
	defaultOutputName = "geoip.metadb"
	defaultOutputDir  = filepath.Join("./", "output", "mihomo")
)

func init() {
	lib.RegisterOutputConfigCreator(typeMihomoMetaDBOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return newMihomoMetaDBOut(action, data)
	})
	lib.RegisterOutputConverter(typeMihomoMetaDBOut, &mihomoMetaDBOut{
		Description: descMihomoMetaDBOut,
	})
}

func newMihomoMetaDBOut(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
	var tmp struct {
		OutputName string     `json:"outputName"`
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

	if tmp.OutputName == "" {
		tmp.OutputName = defaultOutputName
	}

	if tmp.OutputDir == "" {
		tmp.OutputDir = defaultOutputDir
	}

	return &mihomoMetaDBOut{
		Type:        typeMihomoMetaDBOut,
		Action:      action,
		Description: descMihomoMetaDBOut,
		OutputName:  tmp.OutputName,
		OutputDir:   tmp.OutputDir,
		Want:        tmp.Want,
		Exclude:     tmp.Exclude,
		OnlyIPType:  tmp.OnlyIPType,
	}, nil
}

type mihomoMetaDBOut struct {
	Type        string
	Action      lib.Action
	Description string
	OutputName  string
	OutputDir   string
	Want        []string
	Exclude     []string
	OnlyIPType  lib.IPType
}

func (m *mihomoMetaDBOut) GetType() string {
	return m.Type
}

func (m *mihomoMetaDBOut) GetAction() lib.Action {
	return m.Action
}

func (m *mihomoMetaDBOut) GetDescription() string {
	return m.Description
}

// Output menulis geoip.metadb. Tidak seperti maxmindMMDB, tidak ada
// overwriteList di sini: satu network bisa menampung beberapa nama list
// sekaligus, jadi urutan tulis tidak mengubah hasil.
func (m *mihomoMetaDBOut) Output(container lib.Container) error {
	writer, err := mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType:            databaseTypeMeta,
			IPVersion:               6,
			RecordSize:              24,
			Inserter:                inserter.ReplaceWith,
			DisableIPv4Aliasing:     true,
			IncludeReservedNetworks: true,
		},
	)
	if err != nil {
		return err
	}

	prefixes, codesByPrefix, err := m.collect(container)
	if err != nil {
		return err
	}
	if len(prefixes) == 0 {
		return fmt.Errorf("❌ [type %s | action %s] no CIDR to write, output file skipped", m.Type, m.Action)
	}

	// Network yang lebih luas ditulis lebih dulu. Dengan begitu writer.Get pada
	// network turunan menemukan record induknya, lalu kodenya digabung, sehingga
	// 10.10.10.0/24 ikut menjawab "private" seperti induk 10.0.0.0/8.
	slices.SortFunc(prefixes, comparePrefix)

	for _, prefix := range prefixes {
		network := prefixToIPNet(prefix)
		if err := insertMerged(writer, network, codesByPrefix[prefix]); err != nil {
			return err
		}
	}

	return m.writeFile(m.OutputName, writer)
}

// collect membaca seluruh list terpilih dan memetakan setiap CIDR ke daftar
// nama list (huruf kecil) yang memuat CIDR tersebut.
func (m *mihomoMetaDBOut) collect(container lib.Container) ([]netip.Prefix, map[netip.Prefix][]string, error) {
	prefixes := make([]netip.Prefix, 0, 4096)
	codesByPrefix := make(map[netip.Prefix][]string, 4096)

	for _, name := range filterList(container, m.Want, m.Exclude) {
		entry, found := container.GetEntry(name)
		if !found {
			log.Printf("❌ entry %s not found\n", name)
			continue
		}

		prefixList, err := entryPrefixes(entry, m.OnlyIPType)
		if err != nil {
			return nil, nil, fmt.Errorf("❌ [type %s | action %s] %w", m.Type, m.Action, err)
		}

		// Nama list harus huruf kecil: LookupCode pada tipe Meta-geoip0
		// mengembalikan isi record apa adanya, sementara payload aturan GEOIP
		// di mihomo sudah di-ToLower saat dibaca dari config.
		code := strings.ToLower(entry.GetName())

		for _, prefix := range prefixList {
			if _, seen := codesByPrefix[prefix]; !seen {
				prefixes = append(prefixes, prefix)
			}
			codesByPrefix[prefix] = appendUnique(codesByPrefix[prefix], code)
		}
	}

	return prefixes, codesByPrefix, nil
}

// insertMerged menggabungkan kode baru dengan record network induk yang sudah
// terbaca di tree, lalu menimpa record pada network tersebut.
func insertMerged(writer *mmdbwriter.Tree, network *net.IPNet, codes []string) error {
	_, existing := writer.Get(network.IP)

	merged := codes
	switch record := existing.(type) {
	case nil:
	case mmdbtype.String:
		merged = appendUniqueAll([]string{string(record)}, codes)
	case mmdbtype.Slice:
		previous := make([]string, 0, len(record))
		for _, item := range record {
			value, ok := item.(mmdbtype.String)
			if !ok {
				return fmt.Errorf("unexpected Meta-geoip0 record item %T in tree", item)
			}
			previous = append(previous, string(value))
		}
		merged = appendUniqueAll(previous, codes)
	default:
		return fmt.Errorf("unexpected Meta-geoip0 record type %T in tree", existing)
	}

	return writer.Insert(network, recordValue(merged))
}

// recordValue memakai string bila hanya ada satu kode, dan array bila lebih.
// Bentuk ini yang dibaca mihomo sebagai string atau []any pada LookupCode.
func recordValue(codes []string) mmdbtype.DataType {
	if len(codes) == 1 {
		return mmdbtype.String(codes[0])
	}

	value := make(mmdbtype.Slice, 0, len(codes))
	for _, code := range codes {
		value = append(value, mmdbtype.String(code))
	}
	return value
}

func appendUnique(dst []string, code string) []string {
	return appendUniqueAll(dst, []string{code})
}

func appendUniqueAll(dst, codes []string) []string {
	for _, code := range codes {
		if !slices.Contains(dst, code) {
			dst = append(dst, code)
		}
	}
	return dst
}

// comparePrefix mengurutkan dari network terluas ke terkecil, lalu menurut urutan
// alamat, supaya hasil build bisa direproduksi.
func comparePrefix(a, b netip.Prefix) int {
	if c := cmp.Compare(a.Bits(), b.Bits()); c != 0 {
		return c
	}
	return a.Addr().Compare(b.Addr())
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	addr := prefix.Addr()
	return &net.IPNet{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), addr.BitLen()),
	}
}

func (m *mihomoMetaDBOut) writeFile(filename string, writer *mmdbwriter.Tree) error {
	if err := os.MkdirAll(m.OutputDir, 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(filepath.Join(m.OutputDir, filename), os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return err
	}

	_, err = writer.WriteTo(f)
	if err != nil {
		_ = f.Close()
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	log.Printf("✅ [%s] %s --> %s", m.Type, filename, m.OutputDir)

	return nil
}
