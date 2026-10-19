package mihomo

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Loyalsoldier/geoip/lib"
	"github.com/oschwald/maxminddb-golang"
)

// TestOutputMetaDB memastikan tiga hal yang tidak bisa dilakukan output
// maxmindMMDB: satu network menjawab beberapa nama list, network turunan
// mewarisi kode induknya, dan seluruh kode tertulis huruf kecil.
func TestOutputMetaDB(t *testing.T) {
	container := lib.NewContainer()

	private := lib.NewEntry("private")
	lokal := lib.NewEntry("lokal")
	us := lib.NewEntry("US")
	google := lib.NewEntry("google")

	for cidr, e := range map[string]*lib.Entry{
		"10.0.0.0/8":    private,
		"10.10.10.0/24": lokal,
		"1.1.1.0/24":    us,
		"1.1.1.0/25":    google,
		"8.8.8.8/32":    google,
		"2001:db8::/32": us,
	} {
		if err := e.AddPrefix(cidr); err != nil {
			t.Fatalf("AddPrefix(%s): %v", cidr, err)
		}
	}

	for _, e := range []*lib.Entry{private, lokal, us, google} {
		if err := container.Add(e); err != nil {
			t.Fatalf("container.Add(%s): %v", e.GetName(), err)
		}
	}

	dir := t.TempDir()
	converter, err := newMihomoMetaDBOut(lib.ActionOutput, json.RawMessage(fmt.Sprintf(`{"outputDir": %q}`, dir)))
	if err != nil {
		t.Fatalf("newMihomoMetaDBOut: %v", err)
	}
	if err := converter.Output(container); err != nil {
		t.Fatalf("Output: %v", err)
	}

	db, err := maxminddb.Open(filepath.Join(dir, defaultOutputName))
	if err != nil {
		t.Fatalf("buka hasil: %v", err)
	}
	defer db.Close()

	if got := db.Metadata.DatabaseType; got != databaseTypeMeta {
		t.Errorf("DatabaseType = %q, ingin %q", got, databaseTypeMeta)
	}

	cases := []struct {
		ip   string
		want any
	}{
		{"10.10.10.5", []any{"private", "lokal"}}, // turunan mewarisi kode induk
		{"10.9.9.9", "private"},
		{"1.1.1.10", []any{"us", "google"}},
		{"1.1.1.200", "us"}, // di luar /25, hanya induk
		{"8.8.8.8", "google"},
		{"2001:db8::1", "us"},
		{"1.0.0.1", nil},
	}

	for _, c := range cases {
		var record any
		if err := db.Lookup(net.ParseIP(c.ip), &record); err != nil {
			t.Errorf("Lookup(%s): %v", c.ip, err)
			continue
		}
		if !reflect.DeepEqual(record, c.want) {
			t.Errorf("Lookup(%s) = %#v, ingin %#v", c.ip, record, c.want)
		}
	}
}

// TestOutputWantedList memastikan wantedList menyaring isi berkas.
func TestOutputWantedList(t *testing.T) {
	container := lib.NewContainer()

	google := lib.NewEntry("google")
	if err := google.AddPrefix("8.8.8.8/32"); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}
	private := lib.NewEntry("private")
	if err := private.AddPrefix("10.0.0.0/8"); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}
	for _, e := range []*lib.Entry{google, private} {
		if err := container.Add(e); err != nil {
			t.Fatalf("container.Add: %v", err)
		}
	}

	dir := t.TempDir()
	converter, err := newMihomoMetaDBOut(lib.ActionOutput, json.RawMessage(fmt.Sprintf(
		`{"outputDir": %q, "wantedList": ["GOOGLE"]}`, dir)))
	if err != nil {
		t.Fatalf("newMihomoMetaDBOut: %v", err)
	}
	if err := converter.Output(container); err != nil {
		t.Fatalf("Output: %v", err)
	}

	db, err := maxminddb.Open(filepath.Join(dir, defaultOutputName))
	if err != nil {
		t.Fatalf("buka hasil: %v", err)
	}
	defer db.Close()

	var record any
	if err := db.Lookup(net.ParseIP("10.10.10.5"), &record); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if record != nil {
		t.Errorf("Lookup(10.10.10.5) = %#v, ingin kosong karena list tidak diminta", record)
	}

	record = nil
	if err := db.Lookup(net.ParseIP("8.8.8.8"), &record); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if record != any("google") {
		t.Errorf("Lookup(8.8.8.8) = %#v, ingin \"google\"", record)
	}
}
