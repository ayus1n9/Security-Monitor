import re
from datetime import datetime
import ipaddress

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


if __name__ == '__main__':
    tests = [
        '2025-01-15 08:23:11,192.168.1.10,10.0.0.5,22,FAILED,admin',
        '',
        'this is not a log line',
        '2025-01-15 08:23:11,192.168.1.10,10.0.0.5,22,FAILED,admin\n',  # note trailing \n
    ]
    for t in tests:
        print(f'IN : {t!r}')
        print(f'OUT: {parse_log_line(t)}')
        print('-' * 60)

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
    except FileNotFoundError:
        print(f"[warn] Blocklist file not found: {filepath}")
    return networks


if __name__ == '__main__':
    # Reuse the previous test block; add this at the bottom for a quick check.
    nets = load_blocklist('data/blocklist.txt')
    print(f"Loaded {len(nets)} networks:")
    for n in nets:
        print(f"  {n}")