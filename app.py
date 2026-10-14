import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024  # URLs only; keep requests small

MAX_HOPS = 8
TIMEOUT = (3.5, 5)
REDIRECT_CODES = {301, 302, 303, 307, 308}
USER_AGENT = "ShortlinkResolver/1.0 (+safe redirect inspection)"


def validate_public_url(raw_url):
    """Allow only public HTTP(S) destinations; reject local/private addresses."""
    if not isinstance(raw_url, str) or len(raw_url) > 2048:
        raise ValueError("URL tidak valid atau terlalu panjang.")
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Masukkan URL terlebih dahulu.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Hanya URL HTTP atau HTTPS yang didukung.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Hostname tidak valid; URL dengan username/password ditolak.")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Port URL tidak valid.")
    expected_port = 443 if parsed.scheme == "https" else 80
    if port not in (None, expected_port):
        raise ValueError("Port khusus tidak diizinkan.")

    host = parsed.hostname.rstrip(".")
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        raise ValueError("Alamat lokal tidak diizinkan.")
    try:
        ip = ipaddress.ip_address(host)
        addresses = [ip]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port or expected_port, type=socket.SOCK_STREAM)
            addresses = [ipaddress.ip_address(info[4][0]) for info in infos]
        except socket.gaierror:
            raise ValueError("Domain tidak dapat ditemukan (DNS gagal).")
    if not addresses or any(not addr.is_global for addr in addresses):
        raise ValueError("URL menuju alamat IP privat atau khusus, sehingga diblokir.")
    return raw_url


def inspect_url(start_url):
    current = validate_public_url(start_url)
    hops = []
    seen = set()
    final_status = None
    content_type = ""
    page_sample = ""
    for _ in range(MAX_HOPS + 1):
        current = validate_public_url(current)
        if current in seen:
            return {"ok": True, "final_url": current, "hops": hops,
                    "message": "Loop redirect terdeteksi.", "manual_required": True,
                    "status": final_status, "content_type": content_type}
        seen.add(current)
        try:
            # No automatic redirects: validate every Location before following it.
            with requests.get(current, allow_redirects=False, stream=True,
                              timeout=TIMEOUT, headers={"User-Agent": USER_AGENT,
                                                       "Accept": "text/html,application/xhtml+xml,*/*;q=0.5"}) as resp:
                final_status = resp.status_code
                content_type = resp.headers.get("Content-Type", "")[:160]
                if resp.status_code in REDIRECT_CODES:
                    location = resp.headers.get("Location")
                    if not location:
                        return {"ok": True, "final_url": current, "hops": hops,
                                "message": "Respons redirect tidak memiliki Location.",
                                "manual_required": True, "status": final_status,
                                "content_type": content_type}
                    target = urljoin(current, location)
                    target = validate_public_url(target)
                    hops.append({"status": resp.status_code, "url": current, "to": target})
                    current = target
                    continue
                if "text/html" in content_type.lower():
                    try:
                        page_sample = next(resp.iter_content(chunk_size=4096), b"")[:4096].decode("utf-8", "ignore").lower()
                    except requests.RequestException:
                        page_sample = ""
                break
        except requests.RequestException as exc:
            return {"ok": False, "error": f"Gagal mengakses URL: {type(exc).__name__}",
                    "hops": hops}
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "hops": hops}
    else:
        return {"ok": True, "final_url": current, "hops": hops,
                "message": f"Batas {MAX_HOPS} redirect tercapai.",
                "manual_required": True, "status": final_status,
                "content_type": content_type}

    markers = ("captcha", "verify you are human", "human verification", "complete the survey",
               "please verify", "security check", "enable javascript", "cloudflare")
    manual_required = any(marker in page_sample for marker in markers)
    message = ("Halaman tampaknya membutuhkan verifikasi manual atau JavaScript. Resolver tidak melewati kontrol tersebut."
               if manual_required else "Pemeriksaan selesai. Jika halaman memakai JavaScript atau verifikasi, URL tujuan mungkin belum terdeteksi.")
    return {"ok": True, "final_url": current, "hops": hops, "message": message,
            "manual_required": manual_required, "status": final_status,
            "content_type": content_type}


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/resolve")
def resolve():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    try:
        result = inspect_url(url)
        return jsonify(result), (200 if result.get("ok") else 400)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc), "hops": []}), 400


@app.get("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    # Use a production WSGI server for public deployment.
    app.run(host="127.0.0.1", port=5000, debug=False)
