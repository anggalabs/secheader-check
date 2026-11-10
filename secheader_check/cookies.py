"""Pemeriksaan atribut keamanan cookie dari header Set-Cookie.

Catatan penting: header Set-Cookie TIDAK boleh digabung dengan koma seperti
header lain, karena atribut Expires sendiri mengandung koma
(mis. "Expires=Wed, 21 Oct 2026 07:28:00 GMT"). Karena itu modul ini membaca
setiap Set-Cookie secara terpisah.

Nilai cookie sengaja tidak pernah ditampilkan, hanya namanya, karena nilai
cookie sesi setara dengan kredensial login.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

from .headers import FAIL, PASS, WARN, Finding

# Nama cookie yang kemungkinan besar menyimpan sesi/autentikasi.
SENSITIVE_NAME = re.compile(r"sess|auth|token|sid|jwt|login|remember|csrf|xsrf", re.IGNORECASE)
# Cookie anti-CSRF memang sering perlu dibaca JavaScript, jadi tanpa HttpOnly itu wajar.
JS_READABLE_BY_DESIGN = re.compile(r"csrf|xsrf", re.IGNORECASE)


@dataclass
class Cookie:
    name: str
    attributes: dict = field(default_factory=dict)  # key huruf kecil -> nilai ("" jika flag)

    @property
    def secure(self) -> bool:
        return "secure" in self.attributes

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attributes

    @property
    def samesite(self) -> str:
        return self.attributes.get("samesite", "").lower()

    @property
    def sensitive(self) -> bool:
        return bool(SENSITIVE_NAME.search(self.name))


def get_set_cookie_headers(raw) -> List[str]:
    """Ambil semua header Set-Cookie tanpa digabung.

    `raw` bisa berupa http.client.HTTPMessage (punya get_all) atau dict
    (dipakai di unit test; nilainya str atau list of str).
    """
    if hasattr(raw, "get_all"):
        return list(raw.get_all("Set-Cookie") or [])
    for key, value in raw.items():
        if key.lower() == "set-cookie":
            return list(value) if isinstance(value, (list, tuple)) else [value]
    return []


def parse_set_cookie(header: str) -> Cookie:
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return Cookie(name=name, attributes=attrs)


def cookie_problems(cookie: Cookie, is_https: bool) -> List[str]:
    problems = []
    if is_https and not cookie.secure:
        problems.append("tanpa Secure")
    if not cookie.httponly and not JS_READABLE_BY_DESIGN.search(cookie.name):
        problems.append("tanpa HttpOnly")
    if cookie.samesite == "none" and not cookie.secure:
        problems.append("SameSite=None tanpa Secure (ditolak browser modern)")
    elif not cookie.samesite:
        problems.append("tanpa SameSite")
    return problems


def check_cookies(raw_headers, is_https: bool) -> Finding:
    name = "Cookie"
    cookies = [parse_set_cookie(h) for h in get_set_cookie_headers(raw_headers)]
    if not cookies:
        return Finding(name, PASS, "info", "Halaman ini tidak memasang cookie.")

    details = []
    serious = False
    for c in cookies:
        problems = cookie_problems(c, is_https)
        if not problems:
            continue
        details.append(f"{c.name} ({', '.join(problems)})")
        # Masalah serius: cookie sesi yang bisa dicuri lewat XSS atau HTTP biasa.
        if c.sensitive and any(p in ("tanpa Secure", "tanpa HttpOnly") for p in problems):
            serious = True

    if not details:
        return Finding(name, PASS, "medium",
                       f"{len(cookies)} cookie, semua memakai atribut keamanan yang baik.")
    message = "Atribut kurang: " + "; ".join(details) + "."
    recommendation = ("Set cookie sesi dengan: Secure; HttpOnly; SameSite=Lax "
                      "(atau Strict untuk aplikasi sensitif).")
    if serious:
        return Finding(name, FAIL, "medium", message, recommendation)
    return Finding(name, WARN, "low", message, recommendation)
