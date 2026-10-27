"""Linha de comando: `python3 -m url_listening analyze <url>` ou `serve`."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path

from .analyzer import Analyzer, Report
from .config import Settings
from .web import serve


def _print_report(report: Report) -> None:
    print(f"\nURL analisada : {report.input_url}")
    print(f"Destino final : {report.final_url or '(não alcançado)'}")
    if report.title:
        print(f"Título        : {report.title}")
    print("\nCadeia de redirecionamento:")
    for i, hop in enumerate(report.hops, 1):
        extra = f" ({hop.error})" if hop.error else ""
        print(f"  {i:>2}. [{hop.kind:<5}] {hop.status or '---'}  {hop.url}{extra}")
    print("\nDomínios encontrados:")
    for entry in report.domains:
        print(f"  {entry.verdict:<13} {entry.host:<45} {'; '.join(entry.reasons)}")
    for warning in report.warnings:
        print(f"\n[aviso] {warning}")
    print("\nLista para o objeto de bloqueio (domínios):")
    for domain in report.blocklist:
        print(f"  {domain}")


def _write_output(report: Report, path: Path) -> None:
    if path.suffix == ".json":
        path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    elif path.suffix == ".csv":
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["host", "dominio", "veredito", "origem", "motivo", "ips", "cnames"])
            for e in report.domains:
                writer.writerow([e.host, e.registrable, e.verdict, ",".join(e.sources),
                                 "; ".join(e.reasons), " ".join(e.ips), " ".join(e.cnames)])
    else:
        path.write_text("\n".join(report.blocklist) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="url_listening", description="Mapeia domínios de um site para bloqueio no webfilter.")
    parser.add_argument("-v", "--verbose", action="store_true", help="log detalhado")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="analisa uma ou mais URLs")
    analyze.add_argument("urls", nargs="+")
    analyze.add_argument("--no-variants", action="store_true", help="não testa domínios espelho (.net, .xxx, ...)")
    analyze.add_argument("--json", action="store_true", help="imprime o relatório em JSON")
    analyze.add_argument("-o", "--output", type=Path, help="salva em .txt (lista), .csv ou .json")

    sub.add_parser("serve", help="sobe a interface web local")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    settings = Settings()

    if args.command == "serve":
        serve(settings)
        return 0

    analyzer = Analyzer(settings)
    merged: set[str] = set()
    for url in args.urls:
        try:
            report = analyzer.analyze(url, check_variants=not args.no_variants)
        except ValueError as exc:
            print(f"erro: {exc}", file=sys.stderr)
            return 2
        merged |= set(report.blocklist)
        if args.json:
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        else:
            _print_report(report)
        if args.output:
            out = args.output if len(args.urls) == 1 else args.output.with_stem(f"{args.output.stem}_{report.blocklist[0] if report.blocklist else 'site'}")
            _write_output(report, out)
            print(f"\nSalvo em {out}", file=sys.stderr)
    if len(args.urls) > 1 and not args.json:
        print("\nLista consolidada de todas as URLs:")
        print("\n".join(f"  {d}" for d in sorted(merged)))
    return 0
