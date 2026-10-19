package main

import "testing"

// newTestMap membangun ListInfoMap dari nama list. Exclude hanya bekerja pada
// kunci map, jadi isinya tidak perlu diisi.
func newTestMap(names ...string) *ListInfoMap {
	lm := &ListInfoMap{}
	for _, name := range names {
		info := NewListInfo()
		info.Name = fileName(name)
		(*lm)[fileName(name)] = info
	}
	return lm
}

func TestExclude(t *testing.T) {
	lm := newTestMap("CN", "GEOLOCATION-CN", "AWS-CN", "GOOGLE")
	if err := lm.Exclude("*-cn"); err != nil {
		t.Fatalf("Exclude: %v", err)
	}
	if _, ok := (*lm)["CN"]; !ok {
		t.Error("CN dibuang, padahal mihomo membutuhkannya untuk verifikasi geodata")
	}
	for _, name := range []fileName{"GEOLOCATION-CN", "AWS-CN"} {
		if _, ok := (*lm)[name]; ok {
			t.Errorf("%s masih ada, seharusnya dibuang", name)
		}
	}
	if _, ok := (*lm)["GOOGLE"]; !ok {
		t.Error("GOOGLE ikut terbuang")
	}
}

func TestExcludePolaKosong(t *testing.T) {
	lm := newTestMap("CN", "GOOGLE")
	if err := lm.Exclude(""); err != nil {
		t.Fatalf("Exclude: %v", err)
	}
	if len(*lm) != 2 {
		t.Errorf("jumlah list berubah: %d, ingin 2", len(*lm))
	}
}

func TestExcludePolaTidakValid(t *testing.T) {
	lm := newTestMap("CN")
	if err := lm.Exclude("[CN"); err == nil {
		t.Error("pola rusak seharusnya mengembalikan error")
	}
}
