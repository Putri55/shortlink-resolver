# LinkScope — Shortlink Resolver

Website Flask untuk memeriksa rantai redirect HTTP/HTTPS publik. Ini bukan bypass CAPTCHA, login, survei, atau kontrol akses.

## Jalankan lokal

1. Pasang Python 3.10+.
2. Buka terminal di folder proyek.
3. Buat virtual environment (opsional tetapi disarankan):
   - Windows: `py -m venv .venv` lalu `.venv\\Scripts\\activate`
   - macOS/Linux: `python3 -m venv .venv` lalu `source .venv/bin/activate`
4. Pasang dependensi: `pip install -r requirements.txt`
5. Jalankan: `python app.py`
6. Buka `http://127.0.0.1:5000`.

## Deploy gratis (contoh: Render atau layanan Python sejenis)

1. Buat repository GitHub dan unggah seluruh isi folder ini.
2. Di layanan hosting, buat **Web Service** dari repository tersebut.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app --workers 2 --threads 4 --timeout 20`
5. Pilih paket gratis jika tersedia di akun/region Anda, lalu deploy.
6. Buka URL HTTPS yang diberikan layanan hosting.

Paket gratis, sleep saat tidak aktif, batas trafik, dan kebijakan penyedia dapat berubah. Jangan mengandalkan layanan gratis untuk produksi penting.

## API

`POST /api/resolve` dengan JSON `{"url":"https://example.com/short"}`.

## Catatan keamanan

- Pemeriksaan DNS/IP menolak alamat privat/non-global, tetapi pemeriksaan URL dari server tetap memiliki risiko SSRF dan DNS rebinding. Untuk layanan publik, tambahkan rate limiting, logging minimal, isolasi jaringan egress, dan pemeriksaan DNS yang tahan rebinding.
- Batasi pemakaian melalui reverse proxy/WAF jika dipublikasikan. Jangan menaruh rahasia di frontend.
- Website hanya mengikuti redirect HTTP standar. Tujuan yang dihasilkan JavaScript, tombol Continue, cookie, CAPTCHA, login, atau survei tidak otomatis dilewati.
