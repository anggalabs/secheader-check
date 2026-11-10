"""Antarmuka command line."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .report import render_json, render_text, use_color
from .scanner import scan

EXIT_OK, EXIT_BELOW_THRESHOLD, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secheader-check",
        description="Periksa header keamanan HTTP dan sertifikat TLS sebuah situs.",
        epilog="Contoh: secheader-check example.com github.com --fail-under 70",
    )
    p.add_argument("targets", nargs="*", help="Domain atau URL (default https:// jika skema tidak ditulis)")
    p.add_argument("-f", "--file", help="File berisi daftar target, satu per baris (# untuk komentar)")
    p.add_argument("-t", "--timeout", type=float, default=10.0, help="Timeout per koneksi, detik (default 10)")
    p.add_argument("--json", action="store_true", help="Keluarkan hasil dalam format JSON")
    p.add_argument("--no-tls", action="store_true", help="Lewati pemeriksaan sertifikat TLS")
    p.add_argument("--no-color", action="store_true", help="Matikan warna di output")
    p.add_argument("--fail-under", type=int, metavar="SKOR",
                   help="Exit code 1 jika ada target dengan skor di bawah nilai ini (berguna untuk CI)")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def read_targets(path: str) -> List[str]:
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    targets = list(args.targets)
    if args.file:
        try:
            targets += read_targets(args.file)
        except OSError as exc:
            parser.error(f"tidak bisa membaca file: {exc}")
    if not targets:
        parser.error("berikan minimal satu target atau --file")

    color = use_color(args.no_color)
    results = []
    for i, target in enumerate(targets):
        result = scan(target, timeout=args.timeout, check_tls=not args.no_tls)
        results.append(result)
        if not args.json:
            if i:
                print("\n" + "-" * 60 + "\n")
            print(render_text(result, color))

    if args.json:
        print(render_json(results))

    if any(r.error for r in results):
        return EXIT_ERROR
    if args.fail_under is not None and any(r.score < args.fail_under for r in results):
        return EXIT_BELOW_THRESHOLD
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
