#!/usr/bin/env python3
"""
Domain 4 Toolkit — entry point.
Usage:
    python3 main.py analyze --log data/sample.log --blocklist data/blocklist.txt
    python3 main.py ir
"""

import argparse
import sys
import log_analyzer
import ir_tracker

DEFAULT_ALLOWED_PORTS = '22,80,443,53,123'

def parse_ports(s):
    """'22,80,443' -> {22, 80, 443}"""
    try:
        return {int(p.strip()) for p in s.split(',') if p.strip()}
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid port list: {s}") from e

def build_parser():
    parser = argparse.ArgumentParser(
        prog='domain4-toolkit',
        description='Firewall log analyzer + Incident Response tracker'
    )
    sub = parser.add_subparsers(dest='command', required=True)

    a = sub.add_parser('analyze', help='Analyze a firewall/server log')
    a.add_argument('--log', required=True, help='Path to log file')
    a.add_argument('--blocklist', required=True, help='Path to blocklist file')
    a.add_argument('--allowed-ports', type=parse_ports, default=parse_ports(DEFAULT_ALLOWED_PORTS), help=f"Comma-separated allowed ports " f"(default: {DEFAULT_ALLOWED_PORTS})")
    a.add_argument('--threshold', type=int, default=5, help='Brute-force failure threshold (default: 5)')
    a.add_argument('--window', type=int, default=5, help='Brute-force window in minutes (default: 5)')
    a.add_argument('--output', default=None, help='Optional path to also write the report')
    sub.add_parser('ir', help='Launch the interactive IR tracker')
    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == 'analyze':
        log_analyzer.run_analysis(
            log_path=args.log,
            blocklist_path=args.blocklist,
            allowed_ports=args.allowed_ports,
            threshold=args.threshold,
            window_minutes=args.window,
            output_path=args.output,
        )
    elif args.command == 'ir':
        ir_tracker.ir_menu()
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()