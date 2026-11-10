"""Menggabungkan pengambilan header (HTTP) dan pemeriksaan TLS untuk satu target."""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

from . import __version__
from .headers import Finding, analyze_headers, compute_score, grade
from .tls import TLSInfo, get_tls_info, tls_findings

USER_AGENT = f"secheader-check/{__version__}"


@dataclass
class ScanResult:
    target: str
    final_url: str = ""
    status_code: Optional[int] = None
    findings: List[Finding] = field(default_factory=list)
    tls: Optional[TLSInfo] = None
    score: Optional[int] = None
    grade: str = ""
    error: str = ""


def normalize_target(target: str) -> str:
    target = target.strip()
    if "://" not in target:
        target = "https://" + target
    return target


def fetch_headers(url: str, timeout: float):
    """GET ke URL (mengikuti redirect). Kembalikan (url_akhir, status, header).

    Respons 4xx/5xx tetap punya header, jadi tetap dianalisis.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return resp.geturl(), resp.status, resp.headers
    except urllib.error.HTTPError as exc:
        return exc.geturl(), exc.code, exc.headers


def scan(target: str, timeout: float = 10.0, check_tls: bool = True) -> ScanResult:
    url = normalize_target(target)
    result = ScanResult(target=url)

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        result.error = "URL tidak valid (harus http:// atau https:// dengan hostname)."
        return result

    try:
        final_url, status, headers = fetch_headers(url, timeout)
    except urllib.error.URLError as exc:
        result.error = f"Gagal terhubung: {exc.reason}"
        return result
    except (OSError, ValueError) as exc:
        result.error = f"Gagal terhubung: {exc}"
        return result

    result.final_url = final_url
    result.status_code = status
    final = urlparse(final_url)
    is_https = final.scheme == "https"

    result.findings = analyze_headers(headers, is_https)

    if check_tls and is_https and final.hostname:
        result.tls = get_tls_info(final.hostname, final.port or 443, timeout)
        result.findings.extend(tls_findings(result.tls))

    result.score = compute_score(result.findings)
    result.grade = grade(result.score)
    return result
