import ipaddress
import utils
import re
from collections import defaultdict
from datetime import datetime, timedelta

LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    r',(?P<src_ip>\S+)'
    r',(?P<dst_ip>\S+)'
    r',(?P<dst_port>\d+)'
    r',(?P<action>\S+)'
    r',(?P<username>\S+)'
    r'\s*$'
)

def parse_log_line(line):
    """
    Parse a single log line into a structured dict.
    Returns None if the line doesn't match the expected format.
    Assumes the caller passes a stripped line (no trailing newline).
    """
    match = LOG_PATTERN.match(line)
    if not match:
        return None

    try:
        timestamp = datetime.strptime(match.group('timestamp'), '%Y-%m-%d %H:%M:%S')
        
        dst_port = int(match.group('dst_port'))
        if not 0 <= dst_port <= 65535:
            return None
        
        ipaddress.ip_address(match.group('src_ip'))
        ipaddress.ip_address(match.group('dst_ip'))
    except ValueError:
        return None

    return {
        'timestamp': timestamp,
        'src_ip': match.group('src_ip'),
        'dst_ip': match.group('dst_ip'),
        'dst_port': dst_port,
        'action': match.group('action'),
        'username': match.group('username'),
    }

def load_blocklist(filepath):
    """
    Load IPs and CIDR ranges from a blocklist file.
    Returns a list of IPv4Network objects (singles become /32).
    Lines starting with '#' and blank lines are ignored.
    """
    networks = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                entry = line.strip()
                if not entry or entry.startswith('#'):
                    continue
                try:
                    networks.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    print(f"[warn] Skipping invalid blocklist entry: {entry!r}")
    except (OSError, UnicodeError) as e:
        print(f"[warn] Failed to read blocklist {filepath}: {e}")
    return networks

def load_logs(filepath, stats=None):
    """
    Read a log file line by line and parse each entry.
    If `stats` (a dict) is provided, it will be populated with
    'parsed' and 'skipped' counts.
    Returns a list of parsed dicts.
    """
    entries = []
    skipped = 0

    try:
        with open(filepath, 'r') as f:
            for line in f:
                parsed = parse_log_line(line.strip())
                if parsed is None:
                    skipped += 1
                    continue
                entries.append(parsed)
    except (OSError, UnicodeError) as e:
        print(f"[warn] Failed to read log file {filepath}: {e}")
        if stats is not None:
            stats['parsed'] = 0
            stats['skipped'] = 0
        return []

    if stats is not None:
        stats['parsed'] = len(entries)
        stats['skipped'] = skipped

    print(f"[info] Parsed {len(entries)} entries, skipped {skipped} malformed lines.")
    return entries

def detect_brute_force(logs, threshold=5, window_minutes=5):
    """
    Flag (src_ip, username) pairs with >= threshold FAILED logins
    inside any sliding window of window_minutes.
    Returns a list of findings sorted by count (descending).
    """
    failures = defaultdict(list)
    for entry in logs:
        if entry['action'] != 'FAILED':
            continue
        key = (entry['src_ip'], entry['username'])
        failures[key].append(entry)

    findings = []
    window = timedelta(minutes=window_minutes)

    for (src_ip, username), events in failures.items():
        events.sort(key=lambda e: e['timestamp'])

        start = 0
        n = len(events)
        best_count = 0
        best_first = None
        best_last = None
        best_ports = set()

        for end in range(n):
            while events[end]['timestamp'] - events[start]['timestamp'] > window:
                start += 1
            count = end - start + 1
            if count > best_count:
                best_count = count
                best_first = events[start]['timestamp']
                best_last = events[end]['timestamp']
                best_ports = {e['dst_port'] for e in events[start:end + 1]}

        if best_count >= threshold:
            findings.append({
                'src_ip': src_ip,
                'username': username,
                'count': best_count,
                'first_seen': best_first,
                'last_seen': best_last,
                'dst_ports': best_ports,
            })

    findings.sort(key=lambda f: f['count'], reverse=True)
    return findings

def detect_unusual_ports(logs, allowed_ports):
    """
    Flag traffic to ports outside the allowed_ports set.
    Returns findings aggregated per (src_ip, dst_ip, dst_port).
    """
    buckets = defaultdict(list)

    for entry in logs:
        if entry['dst_port'] in allowed_ports:
            continue
        key = (entry['src_ip'], entry['dst_ip'], entry['dst_port'])
        buckets[key].append(entry)

    findings = []
    for (src_ip, dst_ip, dst_port), events in buckets.items():
        events.sort(key=lambda e: e['timestamp'])
        findings.append({
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'count': len(events),
            'first_seen': events[0]['timestamp'],
            'last_seen': events[-1]['timestamp'],
            'actions': {e['action'] for e in events},
        })

    findings.sort(key=lambda f: f['count'], reverse=True)
    return findings

def detect_bad_ips(logs, blocklist):
    """
    Flag log entries where src_ip or dst_ip matches a blocklist network.
    Returns findings in chronological order.
    """
    if not blocklist:
        return []

    findings = []

    for entry in logs:
        try:
            src = ipaddress.ip_address(entry['src_ip'])
            dst = ipaddress.ip_address(entry['dst_ip'])
        except ValueError:
            continue

        for net in blocklist:
            src_hit = src in net
            dst_hit = dst in net
            if not (src_hit or dst_hit):
                continue

            if src_hit and dst_hit:
                direction = 'both'
                matched = src
            elif src_hit:
                direction = 'src'
                matched = src
            else:
                direction = 'dst'
                matched = dst

            findings.append({
                'timestamp': entry['timestamp'],
                'src_ip': entry['src_ip'],
                'dst_ip': entry['dst_ip'],
                'dst_port': entry['dst_port'],
                'action': entry['action'],
                'username': entry['username'],
                'matched_ip': str(matched),
                'matched_network': str(net),
                'match_direction': direction,
            })
            break

    findings.sort(key=lambda f: f['timestamp'])
    return findings

def generate_report(findings, log_stats, output_path=None):
    """
    Print (and optionally write) a formatted analysis report.
    `findings` is a dict: keys are detection names, values are lists.
    """
    lines = []
    def emit(text=''):
        lines.append(text)
        print(text)
    def fmt_dt(dt):
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    bf   = findings.get('brute_force', [])
    up   = findings.get('unusual_ports', [])
    bi   = findings.get('bad_ips', [])
    ps   = findings.get('port_scan', [])
    dbf  = findings.get('distributed_bf', [])
    oh   = findings.get('off_hours', [])

    emit('=' * 70)
    emit('  FIREWALL / SERVER LOG ANALYSIS REPORT')
    emit(f"  Generated: {fmt_dt(datetime.now())}")
    emit(f"  Log entries parsed: {log_stats.get('parsed', 0)}")
    emit(f"  Malformed lines skipped: {log_stats.get('skipped', 0)}")
    emit('=' * 70)

    emit(f"\n[1] BRUTE FORCE ATTEMPTS: {len(bf)}")
    emit('-' * 70)
    if not bf:
        emit('  (none)')
    else:
        for f in bf:
            ports = ', '.join(str(p) for p in sorted(f['dst_ports']))
            emit(f"  src={f['src_ip']}  user={f['username']}  attempts={f['count']}")
            emit(f"    window : {fmt_dt(f['first_seen'])} -> {fmt_dt(f['last_seen'])}")
            emit(f"    ports  : {ports}")

    emit(f"\n[2] DISTRIBUTED BRUTE FORCE: {len(dbf)}")
    emit('-' * 70)
    if not dbf:
        emit('  (none)')
    else:
        for f in dbf:
            emit(f"  target={f['dst_ip']}:{f['dst_port']}  user={f['username']}  "
                 f"sources={f['unique_sources']}  attempts={f['total_attempts']}")
            emit(f"    window : {fmt_dt(f['first_seen'])} -> {fmt_dt(f['last_seen'])}")
            emit(f"    srcs   : {', '.join(f['sources'][:5])}"
                 + ('  ...' if len(f['sources']) > 5 else ''))

    emit(f"\n[3] PORT SCANS: {len(ps)}")
    emit('-' * 70)
    if not ps:
        emit('  (none)')
    else:
        for f in ps:
            emit(f"  {f['src_ip']} -> {f['dst_ip']}  unique_ports={f['unique_ports']}")
            emit(f"    window : {fmt_dt(f['first_seen'])} -> {fmt_dt(f['last_seen'])}")
            emit(f"    ports  : {', '.join(str(p) for p in f['ports'][:10])}"
                 + ('  ...' if len(f['ports']) > 10 else ''))

    emit(f"\n[4] TRAFFIC ON UNUSUAL PORTS: {len(up)}")
    emit('-' * 70)
    if not up:
        emit('  (none)')
    else:
        for u in up:
            actions = ', '.join(sorted(u['actions']))
            emit(f"  {u['src_ip']} -> {u['dst_ip']}:{u['dst_port']}  "
                 f"count={u['count']}  actions=[{actions}]")

    emit(f"\n[5] OFF-HOURS SUCCESSFUL LOGINS: {len(oh)}")
    emit('-' * 70)
    if not oh:
        emit('  (none)')
    else:
        for e in oh:
            emit(f"  {fmt_dt(e['timestamp'])}  user={e['username']}  "
                 f"from={e['src_ip']}  port={e['dst_port']}  reason={e['reason']}")

    emit(f"\n[6] BLOCKLIST HITS: {len(bi)}")
    emit('-' * 70)
    if not bi:
        emit('  (none)')
    else:
        for b in bi:
            emit(f"  {fmt_dt(b['timestamp'])}  "
                 f"{b['src_ip']} -> {b['dst_ip']}:{b['dst_port']}  "
                 f"{b['action']}  user={b['username']}")
            emit(f"    matched: {b['matched_ip']} ({b['matched_network']})  "
                 f"direction={b['match_direction']}")

    total = len(bf) + len(dbf) + len(ps) + len(up) + len(oh) + len(bi)
    emit('\n' + '=' * 70)
    emit(f"  SUMMARY: {total} total findings")
    emit(f"    Brute force:            {len(bf)}")
    emit(f"    Distributed brute force:{len(dbf)}")
    emit(f"    Port scans:             {len(ps)}")
    emit(f"    Unusual ports:          {len(up)}")
    emit(f"    Off-hours logins:       {len(oh)}")
    emit(f"    Blocklist hits:         {len(bi)}")
    emit('=' * 70)

    if output_path:
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        print(f"\n[info] Report also written to {output_path}")

def run_analysis(log_path=None, blocklist_path=None, allowed_ports=None, threshold=None, window_minutes=None, output_path=None, config=None):
    """
    Top-level orchestrator.
    If `config` is provided, any arg set to None falls back to the config value.
    Loads logs, runs all detections, prints report.
    """
    if config is None:
        config = utils.load_config()

    log_path        = log_path        or config['log_path']
    blocklist_path  = blocklist_path  or config['blocklist_path']
    if allowed_ports is None:
        allowed_ports = set(config['allowed_ports'])
    threshold       = threshold       if threshold       is not None else config['brute_force_threshold']
    window_minutes  = window_minutes  if window_minutes  is not None else config['brute_force_window_minutes']
    output_path     = output_path     or config['report_output']

    log_stats = {}
    logs = load_logs(log_path, stats=log_stats)
    blocklist = load_blocklist(blocklist_path)

    findings = {
        'brute_force':         detect_brute_force(logs, threshold=threshold, window_minutes=window_minutes),
        'unusual_ports':       detect_unusual_ports(logs, allowed_ports),
        'bad_ips':             detect_bad_ips(logs, blocklist),
        'port_scan':           detect_port_scan(logs),
        'distributed_bf':      detect_distributed_brute_force(logs),
        'off_hours':           detect_off_hours_activity(logs),
    }

    generate_report(findings, log_stats, output_path=output_path)
    return findings

def detect_port_scan(logs, port_threshold=10, window_minutes=2):
    """
    Flag (src_ip, dst_ip) pairs where src hits >= port_threshold
    unique destination ports inside any window_minutes sliding window.
    Returns findings sorted by unique_ports descending.
    """
    if not logs:
        return []

    buckets = defaultdict(list)
    for entry in logs:
        key = (entry['src_ip'], entry['dst_ip'])
        buckets[key].append(entry)

    window = timedelta(minutes=window_minutes)
    findings = []

    for (src_ip, dst_ip), events in buckets.items():
        events.sort(key=lambda e: e['timestamp'])

        start = 0
        n = len(events)
        best_unique = 0
        best_first = None
        best_last = None
        best_ports = set()

        for end in range(n):
            while events[end]['timestamp'] - events[start]['timestamp'] > window:
                start += 1

            window_events = events[start:end + 1]
            unique_ports = {e['dst_port'] for e in window_events}

            if len(unique_ports) > best_unique:
                best_unique = len(unique_ports)
                best_first = events[start]['timestamp']
                best_last = events[end]['timestamp']
                best_ports = unique_ports

        if best_unique >= port_threshold:
            findings.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'unique_ports': best_unique,
                'first_seen': best_first,
                'last_seen': best_last,
                'ports': sorted(best_ports),
                'actions': {e['action'] for e in events},
            })

    findings.sort(key=lambda f: f['unique_ports'], reverse=True)
    return findings

def detect_distributed_brute_force(logs, src_threshold=5, window_minutes=5):
    """
    Flag (dst_ip, dst_port, username) targets hit by >= src_threshold
    unique source IPs inside any window_minutes sliding window.
    This is the botnet / distributed brute-force signature.
    Returns findings sorted by unique_sources descending.
    """
    if not logs:
        return []

    failures = [e for e in logs if e['action'] == 'FAILED']
    if not failures:
        return []

    buckets = defaultdict(list)
    for entry in failures:
        key = (entry['dst_ip'], entry['dst_port'], entry['username'])
        buckets[key].append(entry)

    window = timedelta(minutes=window_minutes)
    findings = []

    for (dst_ip, dst_port, username), events in buckets.items():
        events.sort(key=lambda e: e['timestamp'])

        start = 0
        n = len(events)
        best_unique = 0
        best_first = None
        best_last = None
        best_sources = set()
        best_total = 0

        for end in range(n):
            while events[end]['timestamp'] - events[start]['timestamp'] > window:
                start += 1

            window_events = events[start:end + 1]
            unique_sources = {e['src_ip'] for e in window_events}

            if len(unique_sources) > best_unique:
                best_unique = len(unique_sources)
                best_first = events[start]['timestamp']
                best_last = events[end]['timestamp']
                best_sources = unique_sources
                best_total = len(window_events)

        if best_unique >= src_threshold:
            findings.append({
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'username': username,
                'unique_sources': best_unique,
                'total_attempts': best_total,
                'first_seen': best_first,
                'last_seen': best_last,
                'sources': sorted(best_sources),
            })

    findings.sort(key=lambda f: f['unique_sources'], reverse=True)
    return findings

def detect_off_hours_activity(logs, work_start=8, work_end=18, allowed_days=None):
    """
    Flag successful logins outside business hours.
    work_start/work_end: hours (0-23); work_start inclusive, work_end exclusive.
    allowed_days: set of weekday numbers (Mon=0..Sun=6), or None for all days.
    Returns findings sorted chronologically.
    """
    if not logs:
        return []

    findings = []
    for entry in logs:
        if entry['action'] != 'SUCCESS':
            continue

        ts = entry['timestamp']
        reason = None

        if allowed_days is not None and ts.weekday() not in allowed_days:
            reason = 'weekend'
        elif ts.hour < work_start or ts.hour >= work_end:
            reason = 'after-hours'

        if reason is None:
            continue

        findings.append({
            'timestamp': ts,
            'src_ip': entry['src_ip'],
            'dst_ip': entry['dst_ip'],
            'dst_port': entry['dst_port'],
            'username': entry['username'],
            'reason': reason,
        })

    findings.sort(key=lambda f: f['timestamp'])
    return findings
