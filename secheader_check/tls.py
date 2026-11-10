"""Pemeriksaan sertifikat dan protokol TLS memakai modul ssl bawaan Python."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from .headers import FAIL, PASS, WARN, Finding

EXPIRY_WARN_DAYS = 30
EXPIRY_FAIL_DAYS = 7
OLD_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class TLSInfo:
    ok: bool
    error: str = ""
    # "certificate": sertifikat bermasalah (temuan keamanan)
    # "network": gagal konek (DNS/proxy/firewall), bukan bukti situs bermasalah
    error_kind: str = ""
    protocol: str = ""
    cipher: str = ""
    issuer: str = ""
    not_after: str = ""
    days_left: Optional[int] = None


def _name_field(name_tuples, *keys) -> str:
    """Ambil field dari struktur subject/issuer milik ssl.getpeercert()."""
    flat = {k: v for rdn in name_tuples for (k, v) in rdn}
    for key in keys:
        if key in flat:
            return flat[key]
    return ""


def get_tls_info(host: str, port: int = 443, timeout: float = 10.0) -> TLSInfo:
    context = ssl.create_default_context()  # verifikasi sertifikat & hostname aktif
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version() or ""
                cipher = (tls_sock.cipher() or ("",))[0]
    except ssl.SSLCertVerificationError as exc:
        return TLSInfo(ok=False, error_kind="certificate",
                       error=f"Verifikasi sertifikat gagal: {exc.verify_message}")
    except ssl.SSLError as exc:
        return TLSInfo(ok=False, error_kind="certificate", error=f"Handshake TLS gagal: {exc}")
    except OSError as exc:
        return TLSInfo(ok=False, error_kind="network", error=f"Tidak bisa terhubung: {exc}")

    not_after = cert.get("notAfter", "")
    days_left = None
    if not_after:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days

    return TLSInfo(
        ok=True,
        protocol=protocol,
        cipher=cipher,
        issuer=_name_field(cert.get("issuer", ()), "organizationName", "commonName"),
        not_after=not_after,
        days_left=days_left,
    )


def tls_findings(info: TLSInfo) -> List[Finding]:
    if not info.ok and info.error_kind == "network":
        # Severity "info" = tidak mengurangi skor, karena penyebabnya bisa jadi
        # jaringan kita sendiri (mis. proxy kantor/kampus), bukan situsnya.
        return [Finding("Sertifikat TLS", WARN, "info",
                        f"Tidak dapat diperiksa. {info.error}",
                        "Cek koneksi/DNS. Di jaringan dengan proxy, koneksi TLS langsung "
                        "bisa diblokir; gunakan --no-tls.")]
    if not info.ok:
        return [Finding("Sertifikat TLS", FAIL, "high", info.error,
                        "Pastikan sertifikat valid, belum kedaluwarsa, dan cocok dengan domain.")]

    findings = []
    days = info.days_left
    if days is None:
        findings.append(Finding("Sertifikat TLS", WARN, "medium", "Tanggal kedaluwarsa tidak terbaca."))
    elif days < EXPIRY_FAIL_DAYS:
        findings.append(Finding("Sertifikat TLS", FAIL, "high",
                                f"Kedaluwarsa dalam {days} hari ({info.not_after}).",
                                "Perpanjang sertifikat segera / aktifkan perpanjangan otomatis."))
    elif days < EXPIRY_WARN_DAYS:
        findings.append(Finding("Sertifikat TLS", WARN, "medium",
                                f"Kedaluwarsa dalam {days} hari ({info.not_after}).",
                                "Jadwalkan perpanjangan sertifikat."))
    else:
        findings.append(Finding("Sertifikat TLS", PASS, "high",
                                f"Valid, sisa {days} hari. Penerbit: {info.issuer or '-'}."))

    if info.protocol in OLD_PROTOCOLS:
        findings.append(Finding("Protokol TLS", FAIL, "high",
                                f"Memakai protokol usang {info.protocol}.",
                                "Nonaktifkan TLS 1.0/1.1; gunakan TLS 1.2 atau 1.3."))
    else:
        findings.append(Finding("Protokol TLS", PASS, "medium",
                                f"{info.protocol} ({info.cipher})."))
    return findings
