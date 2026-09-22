# Desain: Stabilitas `list.txt` antar-run (carry-forward node hidup)

Tanggal: 2026-09-22
Status: disetujui untuk implementasi
Komponen: `proxy-build/`

## 1. Masalah

Program berjalan harian di GitHub Actions dan menulis `list.txt`. Isi `list.txt`
berubah besar setiap hari walau node-nya sama:

1. **Indeks nama bergeser.** `reindex` (`pipeline.go`) menamai node
   `CC N - ISP` dengan `N` = peringkat setelah di-sort per alamat. Begitu ada
   node masuk/keluar di sebuah negara, semua nomor bergeser dan URL ditulis
   ulang (`#...` diganti). Baris lama benar-benar berubah.
2. **Representatif tidak stabil.** Untuk IP+skema yang sama, `dedupeByIP`
   menyimpan yang pertama ditemukan, sementara urutan append-nya paralel
   (nondeterministik). Node yang sama bisa muncul dengan kredensial berbeda.

Akibatnya konsumen tidak dapat membandingkan `list.txt` antar-hari: node A hari
ini menjadi "node B" besok.

## 2. Tujuan

- Baris lama dipertahankan **apa adanya (URL + nama)** selama node masih hidup.
- Node "yatim" (sudah tidak ada di sumber mana pun) tetap dibawa selama masih
  hidup, dan baru dibuang setelah mati.
- Jika kredensial berubah untuk endpoint yang sama: **pakai URL baru,
  pertahankan nama lama**.
- Output deterministik: input sama → `list.txt` byte-identik.

Non-tujuan: mempercepat runtime; mengubah format baris; mengubah kebijakan
pengujian (retry/timeout/status) selain yang sudah ada.

## 3. Keputusan yang Disepakati

| Topik | Keputusan |
|---|---|
| Yang harus stabil | Baris lama dipertahankan apa adanya (URL + nama) selama hidup |
| Identitas node | `scheme\|host\|port`, lowercase, tanpa resolve DNS |
| Cakupan carry-forward | Node yatim dibawa selama hidup, dibuang saat mati |
| Kredensial berputar | URL baru + nama lama |
| Penomoran nama | Nomor bebas terkecil dipakai ulang (opsi 1b) |
| Dedup kandidat | Ganti `dedupeByIP` → dedup berdasarkan identitas |
| Sumber state | `list.txt` run sebelumnya (branch `asset`) |

## 4. Model Data

```go
type PrevEntry struct {
    Identity string // scheme|host|port
    URL      string
    Name     string // "CC N - ISP" apa adanya
    CC       string // token pertama Name
}
```

- `ProxyEntry` (kandidat hari ini) mendapat method `Identity()` yang memakai
  `extractAddress` yang sudah ada plus port.
- **Port kosong** dianggap `""` dan hanya cocok dengan port kosong lain; tidak
  ada default per skema.
- vmess: `host` = `add`, `port` = `port` dari JSON base64.
- Skema lain: `url.Parse` → `Hostname()` + `Port()`.

## 5. Alur Pipeline

Urutan baru:

1. Fetch + parse kandidat hari ini (seperti sekarang).
2. Dedup kandidat berdasarkan **identitas** (`scheme|host|port`).
3. Baca `list.txt` lama → `[]PrevEntry`.
4. Susun **himpunan uji** = kandidat hari ini ∪ URL lama, didedupe per pasangan
   `(identity, URL)`.
5. Jalankan `testAll` atas himpunan uji → `isAlive(url) bool`.
6. **Rakit output** lewat fungsi murni `mergeOutput(prev, candidates, alive)`:
   - URL lama hidup → tulis baris lama apa adanya.
   - URL lama mati, kandidat URL hidup → tulis URL baru + nama lama.
   - Tidak ada nama lama → identitas baru: alokasi nomor bebas terkecil per CC.
7. Urutkan final (CC, nomor, address) lalu tulis `list.txt`.

Logika merge dipisahkan sebagai fungsi murni dengan `isAlive func(url string)
bool` sebagai parameter, sehingga dapat diuji offline tanpa jaringan.

### Sumber state

Env baru `PreviousListFile` (default `""`). Kosong berarti tanpa carry-forward,
sehingga perilaku lokal tetap sama seperti sekarang.

Parser baris `list.txt`:
- Lewati header `#` dan baris kosong.
- Ambil nama dari `ps` (vmess) atau fragment `#` (skema lain).
- Baris yang tidak dapat diparse dilewati dengan warning.

### Perubahan dedup

`dedupeByIP` (`pipeline.go`) diganti dedup berdasarkan identitas. Cache resolver
tetap efektif karena resolver meng-cache per `scheme|address` (tanpa port),
sehingga host sama dengan port berbeda tidak memicu DNS ulang.

## 6. Determinisme

- Perakitan output tidak boleh bergantung urutan iterasi map. Key dikumpulkan
  lalu diurutkan.
- Node lama dipertahankan urutan dan nomornya.
- Alokasi nomor untuk node baru diurut deterministik.
- Hasil: dua run atas input yang sama menghasilkan `list.txt` byte-identik.

## 7. Penanganan Error dan Edge Case

- `PreviousListFile` tidak ada / baris tak terparse → warning, run tetap jalan.
- Baris lama juga melewati filter negara yang sama dengan kandidat (node yatim
  dari negara yang di-exclude tidak dibawa).
- Nama lama kosong saat kredensial berputar → pakai CC/ISP dari kandidat
  (bukan menghasilkan `# 1 - Unknown`).
- Nama mengandung `%` literal → parser tidak memakai `url.Parse` sebagai gerbang
  validitas dan hanya percent-decode sekali, sehingga baris output sendiri selalu
  bisa dibaca kembali.
- Identitas kandidat tak terbaca → buang kandidat itu saja.
- Satu identitas punya beberapa URL hidup → pakai baris lama bila hidup; jika
  tidak, pilih URL kandidat yang hidup dengan urutan eksplisit: kandidat
  diurutkan `(scheme, host, port, URL)` dan URL pertama yang hidup dipilih.
  Pemilihan tidak boleh bergantung urutan map.
- Identitas yang sudah punya nama lama **tidak** menghasilkan baris kedua untuk
  URL kandidat lain selama baris lama masih hidup.
- Nama dengan CC yang IP-nya berpindah negara → tetap pakai nama lama; nomor
  bisa "melompat" sebagai konsekuensi "baris lama apa adanya".
- Satu map `cc → nomor terpakai` dibangun dari semua nama yang bertahan, lalu
  node baru mengambil nomor bebas terkecil.

## 8. Pengujian

Unit test Go (`_test.go`), tanpa jaringan:

1. Carry-forward baris lama → byte-identik.
2. Kredensial berputar → URL baru + nama lama.
3. Yatim hidup dibawa; yatim mati hilang.
4. Nomor bebas terkecil dipakai ulang; celah terisi; tidak ada tabrakan.
5. Determinisme: permutasi urutan kandidat → output identik.
6. Parser `list.txt`: vmess (`ps`), fragment, header, baris rusak.
7. `PreviousListFile` kosong → perilaku sama seperti sekarang.
8. Identity: host+port vmess vs URL; port kosong tidak digabung sembarangan.

Verifikasi CI (dijalankan pengguna):
- Run pertama: `list.txt` terisi seperti biasa.
- Run kedua: sebagian besar baris identik; diff kecil.
- Metrik: jumlah baris dan jumlah baris yang berubah antar dua run.

## 9. Perubahan Workflow

- Set env `PreviousListFile: GEO/Proxy/list.txt` pada step build di
  `.github/workflows/build_proxy.yml` (hasil clone branch `asset` sudah tersedia
  sebelum `./nodechecker`).
- Tidak ada perubahan lain; `list.txt` tetap disalin ke `asset/Proxy/`.

## 10. File yang Disentuh

- `proxy-build/config.go` — env `PreviousListFile`.
- `proxy-build/pipeline.go` — identitas, parser `list.txt`, dedup, merge murni.
- `proxy-build/main.go` — alur pipeline & perakitan output.
- `proxy-build/*_test.go` — unit test baru.
- `.github/workflows/build_proxy.yml` — env baru.
