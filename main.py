#!/usr/bin/env python3
"""
Usage:
    python3 main.py analyze --log data/sample.log --blocklist data/blocklist.txt
    python3 main.py ir
"""
import argparse
import sys
import utils
import ir_tracker
import log_analyzer

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
    a.add_argument('--log', default=None, help='Path to log file (default: config)')
    a.add_argument('--blocklist', default=None, help='Path to blocklist (default: config)')
    a.add_argument('--allowed-ports', type=parse_ports, default=None, help='Comma-separated allowed ports (default: config)')
    a.add_argument('--threshold', type=int, default=None, help='Brute-force threshold (default: config)')
    a.add_argument('--window', type=int, default=None, help='Brute-force window minutes (default: config)')
    a.add_argument('--output', default=None, help='Path to write the report (default: config)')
    a.add_argument('--config', default='config.json', help='Path to config file (default: config.json)')

    sub.add_parser('ir', help='Launch the interactive IR tracker')
    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == 'analyze':
        config = utils.load_config(args.config)
        log_analyzer.run_analysis(
            log_path=args.log,
            blocklist_path=args.blocklist,
            allowed_ports=args.allowed_ports,
            threshold=args.threshold,
            window_minutes=args.window,
            output_path=args.output,
            config=config,
        )
    elif args.command == 'ir':
        ir_tracker.ir_menu()
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()