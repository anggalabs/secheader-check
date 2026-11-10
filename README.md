# secheader-check

Tool command line untuk memeriksa **header keamanan HTTP** dan **sertifikat TLS** sebuah situs, lalu memberi skor (0–100), grade (A–F), dan saran perbaikan.

- Hanya memakai library bawaan Python (tanpa dependency), jadi bisa jalan di Linux, WSL, macOS, dan Termux.
- Bersifat pasif: tool hanya mengirim satu request GET biasa, sama seperti browser yang membuka halaman.

## Yang diperiksa

| Pemeriksaan | Risiko yang dicegah |
|---|---|
| Strict-Transport-Security (HSTS) | Downgrade ke HTTP, SSL stripping |
| Content-Security-Policy | XSS, injeksi script |
| X-Frame-Options / `frame-ancestors` | Clickjacking |
| X-Content-Type-Options | MIME sniffing |
| Referrer-Policy | Kebocoran URL ke situs lain |
| Permissions-Policy | Penyalahgunaan fitur browser (kamera, mikrofon, dll.) |
| Header `Server` / `X-Powered-By` | Kebocoran versi software |
| Sertifikat TLS | Sertifikat tidak valid atau hampir kedaluwarsa |
| Versi protokol TLS | Protokol usang (TLS 1.0/1.1) |

## Instalasi

Syarat: Python 3.8 atau lebih baru dan git.

```bash
git clone https://github.com/<username>/secheader-check.git
cd secheader-check
```

**Cara 1: langsung jalankan (tanpa instalasi)**

```bash
python3 -m secheader_check example.com
```

**Cara 2: instal sebagai perintah `secheader-check`**

```bash
# Linux/WSL (Ubuntu/Debian baru memblokir pip global, jadi pakai pipx atau venv)
pipx install .
# atau
python3 -m venv .venv && . .venv/bin/activate && pip install .

# Termux
pkg install python git
pip install .
```

## Penggunaan

```bash
secheader-check github.com
secheader-check example.com google.com --no-color
secheader-check -f targets.txt --json > hasil.json
secheader-check example.com --fail-under 70   # exit code 1 jika skor < 70
```

| Opsi | Fungsi |
|---|---|
| `-f, --file` | Baca daftar target dari file (satu per baris) |
| `-t, --timeout` | Timeout koneksi dalam detik (default 10) |
| `--json` | Output JSON untuk diproses tool lain |
| `--no-tls` | Lewati pemeriksaan TLS |
| `--no-color` | Matikan warna |
| `--fail-under N` | Exit code 1 jika ada skor di bawah N (untuk CI/CD) |

Exit code: `0` sukses, `1` skor di bawah `--fail-under`, `2` ada target yang gagal dihubungi.

## Cara penilaian

Skor awal 100. Setiap temuan mengurangi skor sesuai tingkat keparahannya: high 20, medium 10, low 5. Status `WARN` mengurangi setengah bobot.

Grade: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.

Skor ini adalah **heuristik**, bukan audit keamanan lengkap. Header yang bagus tidak menjamin aplikasi bebas celah. Sebaliknya, beberapa header (misalnya CSP) memang sulit diterapkan di situs tertentu.

## Keterbatasan

- Pemeriksaan header otomatis memakai proxy dari variabel `HTTPS_PROXY`. Pemeriksaan TLS tidak: koneksinya langsung ke port 443. Di jaringan yang mewajibkan proxy, hasil TLS akan berstatus "tidak dapat diperiksa" dan tidak mengurangi skor. Gunakan `--no-tls` dalam kondisi itu.
- Hanya halaman yang dituju (setelah redirect) yang diperiksa. Halaman lain di situs yang sama bisa punya header berbeda.
- Analisis CSP memeriksa pola lemah yang umum, bukan validasi CSP yang lengkap.

## Menjalankan test

```bash
python3 -m unittest discover -s tests -v
```

## Etika penggunaan

Header HTTP adalah informasi publik. Meski begitu, gunakan tool ini secara wajar: jangan memindai ribuan domain secara agresif. Laporkan temuan ke pemilik situs secara bertanggung jawab.

## Lisensi

MIT
