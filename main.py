#!/usr/bin/env python3
"""
Usage:
    python3 main.py analyze --log data/sample.log --blocklist data/blocklist.txt
    python3 main.py ir
"""

import argparse
import utils
import ir_tracker
import log_analyzer

def parse_ports(s):
    """Parse and validate a comma-separated list of ports."""
    try:
        ports = {int(p.strip()) for p in s.split(',') if p.strip()}
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            f"Invalid port list: {s}"
        ) from e

    if any(port < 0 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError(
            "Ports must be between 0 and 65535."
        )

    return ports

def positive_int(s):
    """Parse an integer that must be greater than zero."""
    try:
        value = int(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            f"Invalid integer: {s}"
        ) from e

    if value <= 0:
        raise argparse.ArgumentTypeError(
            "Value must be greater than 0."
        )

    return value

def positive_float(s):
    """Parse a floating-point value that must be greater than zero."""
    try:
        value = float(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            f"Invalid number: {s}"
        ) from e

    if value <= 0:
        raise argparse.ArgumentTypeError(
            "Value must be greater than 0."
        )

    return value

def build_parser():
    parser = argparse.ArgumentParser(
        prog='security-toolkit',
        description='Firewall log analyzer + Incident Response tracker'
    )

    sub = parser.add_subparsers(
        dest='command',
        required=True
    )

    a = sub.add_parser(
        'analyze',
        help='Analyze a firewall/server log'
    )

    a.add_argument(
        '--log',
        default=None,
        help='Path to log file (default: config)'
    )

    a.add_argument(
        '--blocklist',
        default=None,
        help='Path to blocklist (default: config)'
    )

    a.add_argument(
        '--allowed-ports',
        type=parse_ports,
        default=None,
        help='Comma-separated allowed ports (default: config)'
    )

    a.add_argument(
        '--threshold',
        type=positive_int,
        default=None,
        help='Brute-force threshold; must be greater than 0 (default: config)'
    )

    a.add_argument(
        '--window',
        type=positive_int,
        default=None,
        help='Brute-force window in minutes; must be greater than 0 (default: config)'
    )

    a.add_argument(
        '--output',
        default=None,
        help='Path to write the report (default: config)'
    )

    a.add_argument(
        '--config',
        default='config.json',
        help='Path to config file (default: config.json)'
    )

    sub.add_parser(
        'ir',
        help='Launch the interactive IR tracker'
    )

    r = sub.add_parser('respond', help='Analyze log AND open an IR incident')
    r.add_argument('--log', default=None)
    r.add_argument('--blocklist', default=None)
    r.add_argument('--allowed-ports', type=parse_ports, default=None)

    r.add_argument(
        '--threshold',
        type=positive_int,
        default=None,
        help='Brute-force threshold; must be greater than 0 (default: config)'
    )
    r.add_argument(
        '--window',
        type=positive_int,
        default=None,
        help='Brute-force window in minutes; must be greater than 0 (default: config)'
    )

    r.add_argument('--output', default=None, help='Path to write the report (default: config)')
    r.add_argument('--config', default='config.json')
    r.add_argument('--name', default=None, help='Incident name (default: auto-generated from log path)')

    w = sub.add_parser('watch', help='Tail a log file and alert in real time')
    w.add_argument('--log', default=None,
                   help='Path to log file (default: config)')
    w.add_argument('--blocklist', default=None,
                   help='Path to blocklist (default: config)')
    w.add_argument('--allowed-ports', type=parse_ports, default=None,
                   help='Comma-separated allowed ports (default: config)')
    w.add_argument(
        '--interval',
        type=positive_float,
        default=2.0,
        help='Poll interval in seconds; must be greater than 0 (default: 2.0)'
    )
    w.add_argument('--threshold', type=positive_int, default=None,
                   help='Brute-force threshold (default: config)')
    w.add_argument('--window', type=positive_int, default=None,
                   help='Brute-force window in minutes (default: config)')
    w.add_argument('--lookback', type=positive_int, default=10,
                   help='Buffer retention in minutes (default: 10)')
    w.add_argument('--from-start', action='store_true',
                   help='Process existing file content on first tick')
    w.add_argument('--config', default='config.json',
                   help='Path to config file (default: config.json)')

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command in ('analyze', 'respond'):
        config = utils.load_config(args.config)
        findings = log_analyzer.run_analysis(
            log_path=args.log,
            blocklist_path=args.blocklist,
            allowed_ports=args.allowed_ports,
            threshold=args.threshold,
            window_minutes=args.window,
            output_path=args.output,
            config=config,
        )

        if args.command == 'respond':
            incident_name = args.name or f"Auto-response: {args.log or config['log_path']}"
            incident = ir_tracker.create_incident_from_findings(
                findings, incident_name
            )

            if incident is None:
                print("[error] Failed to create incident.")
                return

            report_path = args.output or config['report_output']

            if not ir_tracker.link_report_to_incident(incident, report_path):
                print("[warn] Incident was created, but evidence could not be linked.")

            print()
            print('=' * 70)
            print(f"  INCIDENT CREATED: {incident['id']}")
            print(f"  Name    : {incident['name']}")
            print(f"  Severity: {incident['severity'].upper()}")
            print(f"  Status  : {incident['status'].upper()}")
            print(f"  Evidence: {report_path}")
            print('=' * 70)

    elif args.command == 'ir':
        ir_tracker.ir_menu()

    elif args.command == 'watch':
        config = utils.load_config(args.config)
        log_path = args.log or config['log_path']
        blocklist_path = args.blocklist or config['blocklist_path']
        allowed_ports = args.allowed_ports or set(config['allowed_ports'])
        threshold = args.threshold if args.threshold is not None else config['brute_force_threshold']
        window_minutes = args.window if args.window is not None else config['brute_force_window_minutes']

        log_analyzer.watch_log(
            log_path=log_path,
            blocklist_path=blocklist_path,
            allowed_ports=allowed_ports,
            poll_interval=args.interval,
            lookback_minutes=args.lookback,
            threshold=threshold,
            window_minutes=window_minutes,
            from_start=args.from_start,
            max_ticks=None,
        )

if __name__ == '__main__':
    main()
