"""Analisis header keamanan HTTP.

Setiap fungsi check_* menerima dict header (key huruf kecil) dan
mengembalikan satu Finding. Fungsi-fungsi ini murni (tanpa jaringan),
sehingga mudah diuji dengan unit test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Mapping

# Bobot pengurangan skor per tingkat keparahan.
# Status "fail" mengurangi bobot penuh, "warn" mengurangi setengahnya.
SEVERITY_WEIGHT = {"high": 20, "medium": 10, "low": 5, "info": 0}

PASS, WARN, FAIL = "pass", "warn", "fail"


@dataclass
class Finding:
    check: str
    status: str  # pass | warn | fail
    severity: str  # high | medium | low | info
    message: str
    recommendation: str = ""


def normalize_headers(raw) -> Dict[str, str]:
    """Ubah header menjadi dict dengan key huruf kecil.

    Header yang muncul lebih dari sekali digabung dengan koma (sesuai RFC 9110).
    `raw` bisa berupa dict atau objek http.client.HTTPMessage.
    """
    items = raw.items()
    result: Dict[str, str] = {}
    for key, value in items:
        k = key.strip().lower()
        v = value.strip()
        result[k] = f"{result[k]}, {v}" if k in result else v
    return result


# --------------------------------------------------------------------------
# Pemeriksaan individual
# --------------------------------------------------------------------------

HSTS_MIN_AGE = 15552000  # 180 hari, batas minimum yang umum direkomendasikan


def check_hsts(h: Mapping[str, str], is_https: bool) -> Finding:
    name = "Strict-Transport-Security"
    if not is_https:
        return Finding(name, FAIL, "high",
                       "Situs dilayani lewat HTTP biasa (tanpa enkripsi).",
                       "Aktifkan HTTPS dan redirect semua trafik HTTP ke HTTPS.")
    value = h.get("strict-transport-security")
    if not value:
        return Finding(name, FAIL, "high", "Header tidak ada.",
                       "Tambahkan: Strict-Transport-Security: max-age=31536000; includeSubDomains")
    m = re.search(r'max-age\s*=\s*"?(\d+)', value, re.IGNORECASE)
    if not m:
        return Finding(name, FAIL, "high", f"max-age tidak ditemukan/tidak valid: {value}",
                       "Gunakan format: max-age=31536000")
    age = int(m.group(1))
    if age < HSTS_MIN_AGE:
        return Finding(name, WARN, "medium",
                       f"max-age terlalu pendek ({age} detik, kurang dari 180 hari).",
                       "Naikkan max-age minimal ke 15552000 (disarankan 31536000).")
    return Finding(name, PASS, "high", f"Aktif (max-age={age}).")


def parse_csp(value: str) -> Dict[str, List[str]]:
    """Pecah CSP menjadi {directive: [sumber, ...]}.

    Beberapa kebijakan (dipisah koma) digabung secara sederhana; directive
    yang muncul lebih dulu dipakai, sesuai perilaku browser dalam satu kebijakan.
    """
    directives: Dict[str, List[str]] = {}
    for policy in value.split(","):
        for part in policy.split(";"):
            tokens = part.strip().split()
            if tokens:
                directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def check_csp(h: Mapping[str, str]) -> Finding:
    name = "Content-Security-Policy"
    value = h.get("content-security-policy")
    if not value:
        if h.get("content-security-policy-report-only"):
            return Finding(name, WARN, "high",
                           "Hanya mode Report-Only; kebijakan belum ditegakkan.",
                           "Setelah kebijakan teruji, pindahkan ke header Content-Security-Policy.")
        return Finding(name, FAIL, "high", "Header tidak ada.",
                       "Mulai dari kebijakan ketat, mis.: default-src 'self'; object-src 'none'; "
                       "frame-ancestors 'self'")

    directives = parse_csp(value)
    # Yang menentukan perlindungan XSS adalah sumber script:
    # script-src, atau default-src sebagai fallback.
    if "script-src" in directives:
        script_src = directives["script-src"]
    elif "default-src" in directives:
        script_src = directives["default-src"]
    else:
        return Finding(name, WARN, "medium",
                       "Ada, tetapi tanpa script-src/default-src sehingga tidak membatasi script.",
                       "Tambahkan default-src 'self' atau script-src yang ketat.")

    weak = []
    # Browser modern mengabaikan 'unsafe-inline' bila ada nonce atau hash.
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                            for s in script_src)
    if "'unsafe-inline'" in script_src and not has_nonce_or_hash:
        weak.append("'unsafe-inline'")
    if "'unsafe-eval'" in script_src:
        weak.append("'unsafe-eval'")
    if "*" in script_src or any(s in ("http:", "https:", "data:") for s in script_src):
        weak.append("sumber terlalu luas (*, http:, https:, atau data:)")
    if weak:
        return Finding(name, WARN, "medium",
                       "Ada, tetapi sumber script lemah: " + ", ".join(weak) + ".",
                       "Gunakan nonce/hash untuk script inline, hindari 'unsafe-eval' dan wildcard.")
    return Finding(name, PASS, "high", "Ada, dan sumber script dibatasi dengan baik.")


def check_frame_options(h: Mapping[str, str]) -> Finding:
    name = "Clickjacking (X-Frame-Options / frame-ancestors)"
    csp = h.get("content-security-policy", "").lower()
    if "frame-ancestors" in csp:
        return Finding(name, PASS, "medium", "Dilindungi lewat CSP frame-ancestors.")
    xfo = h.get("x-frame-options")
    if not xfo:
        return Finding(name, FAIL, "medium", "Tidak ada X-Frame-Options maupun frame-ancestors.",
                       "Tambahkan: X-Frame-Options: DENY (atau CSP frame-ancestors 'self').")
    if xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        return Finding(name, PASS, "medium", f"X-Frame-Options: {xfo}.")
    return Finding(name, WARN, "medium", f"Nilai X-Frame-Options tidak standar: {xfo}.",
                   "Gunakan DENY atau SAMEORIGIN (ALLOW-FROM sudah usang).")


def check_content_type_options(h: Mapping[str, str]) -> Finding:
    name = "X-Content-Type-Options"
    value = h.get("x-content-type-options", "")
    if value.strip().lower() == "nosniff":
        return Finding(name, PASS, "medium", "nosniff aktif.")
    return Finding(name, FAIL, "medium",
                   "Header tidak ada atau nilainya salah." if not value else f"Nilai salah: {value}",
                   "Tambahkan: X-Content-Type-Options: nosniff")


UNSAFE_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}


def check_referrer_policy(h: Mapping[str, str]) -> Finding:
    name = "Referrer-Policy"
    value = h.get("referrer-policy")
    if not value:
        return Finding(name, WARN, "low", "Header tidak ada (browser memakai default).",
                       "Tambahkan: Referrer-Policy: strict-origin-when-cross-origin")
    # Jika ada beberapa nilai, browser memakai nilai valid terakhir.
    last = [p.strip().lower() for p in value.split(",") if p.strip()][-1]
    if last in UNSAFE_REFERRER:
        return Finding(name, WARN, "low", f"Kebijakan longgar: {last}.",
                       "Gunakan strict-origin-when-cross-origin atau no-referrer.")
    return Finding(name, PASS, "low", f"{last}.")


def check_permissions_policy(h: Mapping[str, str]) -> Finding:
    name = "Permissions-Policy"
    if h.get("permissions-policy"):
        return Finding(name, PASS, "low", "Ada.")
    return Finding(name, WARN, "low", "Header tidak ada.",
                   "Batasi fitur browser yang tidak dipakai, mis.: "
                   "Permissions-Policy: camera=(), microphone=(), geolocation=()")


def check_info_leak(h: Mapping[str, str]) -> Finding:
    name = "Kebocoran informasi server"
    leaks = []
    server = h.get("server")
    if server and re.search(r"\d", server):
        leaks.append(f"Server: {server}")
    powered = h.get("x-powered-by")
    if powered:
        leaks.append(f"X-Powered-By: {powered}")
    if leaks:
        return Finding(name, WARN, "low", "Versi/teknologi terekspos: " + "; ".join(leaks) + ".",
                       "Sembunyikan versi server dan hapus header X-Powered-By.")
    return Finding(name, PASS, "info", "Tidak ada versi server yang terekspos.")


def analyze_headers(raw_headers, is_https: bool) -> List[Finding]:
    """Jalankan semua pemeriksaan header dan kembalikan daftar temuan."""
    h = normalize_headers(raw_headers)
    return [
        check_hsts(h, is_https),
        check_csp(h),
        check_frame_options(h),
        check_content_type_options(h),
        check_referrer_policy(h),
        check_permissions_policy(h),
        check_info_leak(h),
    ]


# --------------------------------------------------------------------------
# Skor
# --------------------------------------------------------------------------

def compute_score(findings: List[Finding]) -> int:
    score = 100
    for f in findings:
        weight = SEVERITY_WEIGHT.get(f.severity, 0)
        if f.status == FAIL:
            score -= weight
        elif f.status == WARN:
            score -= weight // 2
    return max(score, 0)


def grade(score: int) -> str:
    for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= threshold:
            return letter
    return "F"
