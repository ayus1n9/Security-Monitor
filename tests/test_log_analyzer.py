"""
Unit tests for log_analyzer.py.
Run: python3 -m pytest tests/ -v
"""

import pytest
from datetime import datetime

from sentinelog.log_analyzer import (
    parse_log_line,
    detect_brute_force,
    detect_unusual_ports,
    detect_bad_ips,
    detect_port_scan,
    detect_distributed_brute_force,
    detect_off_hours_activity,
)

def make_entry(ts_str, src, dst, port, action='FAILED', user='root'):
    """Build a log entry dict the way parse_log_line would."""
    return {
        'timestamp': datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S'),
        'src_ip': src,
        'dst_ip': dst,
        'dst_port': port,
        'action': action,
        'username': user,
    }

def test_parse_valid_line():
    line = '2025-01-15 08:23:11,192.168.1.10,10.0.0.5,22,FAILED,admin'
    result = parse_log_line(line)
    assert result is not None
    assert result['src_ip'] == '192.168.1.10'
    assert result['dst_ip'] == '10.0.0.5'
    assert result['dst_port'] == 22
    assert result['action'] == 'FAILED'
    assert result['username'] == 'admin'
    assert isinstance(result['timestamp'], datetime)

def test_parse_empty_line_returns_none():
    assert parse_log_line('') is None

def test_parse_garbage_returns_none():
    assert parse_log_line('this is not a log line') is None

def test_parse_bad_timestamp_returns_none():
    line = '2025-99-15 08:23:11,192.168.1.10,10.0.0.5,22,FAILED,admin'
    assert parse_log_line(line) is None

def test_brute_force_fires_above_threshold():
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:30:18', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:30:41', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:31:02', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:31:44', '1.2.3.4', '10.0.0.5', 22),
    ]
    findings = detect_brute_force(logs, threshold=5, window_minutes=5)
    assert len(findings) == 1
    assert findings[0]['src_ip'] == '1.2.3.4'
    assert findings[0]['count'] == 5

def test_brute_force_ignores_below_threshold():
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:30:18', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:30:41', '1.2.3.4', '10.0.0.5', 22),
    ]
    findings = detect_brute_force(logs, threshold=5, window_minutes=5)
    assert findings == []

def test_brute_force_respects_window():
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:35:01', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:40:01', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:45:01', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:50:01', '1.2.3.4', '10.0.0.5', 22),
    ]
    findings = detect_brute_force(logs, threshold=5, window_minutes=5)
    assert findings == []

def test_brute_force_ignores_success():
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.0.0.5', 22, action='SUCCESS'),
        make_entry('2025-01-15 08:30:18', '1.2.3.4', '10.0.0.5', 22, action='SUCCESS'),
        make_entry('2025-01-15 08:30:41', '1.2.3.4', '10.0.0.5', 22, action='SUCCESS'),
        make_entry('2025-01-15 08:31:02', '1.2.3.4', '10.0.0.5', 22, action='SUCCESS'),
        make_entry('2025-01-15 08:31:44', '1.2.3.4', '10.0.0.5', 22, action='SUCCESS'),
    ]
    findings = detect_brute_force(logs, threshold=5, window_minutes=5)
    assert findings == []

def test_unusual_ports_flags_non_allowed():
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.0.0.5', 31337),
    ]
    findings = detect_unusual_ports(logs, allowed_ports={22, 80, 443})
    assert len(findings) == 1
    assert findings[0]['dst_port'] == 31337
    assert findings[0]['count'] == 1


def test_unusual_ports_ignores_allowed():
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.0.0.5', 443),
        make_entry('2025-01-15 08:30:02', '1.2.3.4', '10.0.0.5', 80),
    ]
    findings = detect_unusual_ports(logs, allowed_ports={22, 80, 443})
    assert findings == []


def test_unusual_ports_aggregates_by_flow():
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.0.0.5', 31337),
        make_entry('2025-01-15 08:30:02', '1.2.3.4', '10.0.0.5', 31337),
        make_entry('2025-01-15 08:30:03', '1.2.3.4', '10.0.0.5', 31337),
    ]
    findings = detect_unusual_ports(logs, allowed_ports={22, 80, 443})
    assert len(findings) == 1
    assert findings[0]['count'] == 3

def test_bad_ips_single_match_src():
    import ipaddress
    blocklist = [ipaddress.ip_network('203.0.113.5/32')]
    logs = [
        make_entry('2025-01-15 08:30:01', '203.0.113.5', '10.0.0.5', 22),
    ]
    findings = detect_bad_ips(logs, blocklist)
    assert len(findings) == 1
    assert findings[0]['match_direction'] == 'src'
    assert findings[0]['matched_ip'] == '203.0.113.5'


def test_bad_ips_cidr_match():
    import ipaddress
    blocklist = [ipaddress.ip_network('10.0.0.0/8')]
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.5.5.5', 443),
    ]
    findings = detect_bad_ips(logs, blocklist)
    assert len(findings) == 1
    assert findings[0]['match_direction'] == 'dst'


def test_bad_ips_empty_blocklist():
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.0.0.5', 443),
    ]
    assert detect_bad_ips(logs, []) == []


def test_bad_ips_no_match():
    import ipaddress
    blocklist = [ipaddress.ip_network('203.0.113.5/32')]
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.0.0.5', 443),
    ]
    assert detect_bad_ips(logs, blocklist) == []

def test_port_scan_fires_above_threshold():
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:30:05', '1.2.3.4', '10.0.0.5', 80),
        make_entry('2025-01-15 08:30:09', '1.2.3.4', '10.0.0.5', 443),
        make_entry('2025-01-15 08:30:14', '1.2.3.4', '10.0.0.5', 8080),
        make_entry('2025-01-15 08:30:20', '1.2.3.4', '10.0.0.5', 3389),
    ]
    findings = detect_port_scan(logs, port_threshold=5, window_minutes=2)
    assert len(findings) == 1
    assert findings[0]['unique_ports'] == 5
    assert findings[0]['src_ip'] == '1.2.3.4'
    assert findings[0]['ports'] == sorted([22, 80, 443, 8080, 3389])

def test_port_scan_ignores_repeat_port():
    logs = [
        make_entry(f'2025-01-15 08:30:{i:02d}', '1.2.3.4', '10.0.0.5', 22)
        for i in range(10)
    ]
    assert detect_port_scan(logs, port_threshold=5, window_minutes=2) == []

def test_port_scan_respects_window():
    logs = [
        make_entry('2025-01-15 08:00:00', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:10:00', '1.2.3.4', '10.0.0.5', 80),
        make_entry('2025-01-15 08:20:00', '1.2.3.4', '10.0.0.5', 443),
        make_entry('2025-01-15 08:30:00', '1.2.3.4', '10.0.0.5', 8080),
        make_entry('2025-01-15 08:40:00', '1.2.3.4', '10.0.0.5', 3389),
    ]
    assert detect_port_scan(logs, port_threshold=5, window_minutes=2) == []

def test_port_scan_separates_targets():
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.4', '10.0.0.5', 22),
        make_entry('2025-01-15 08:30:02', '1.2.3.4', '10.0.0.5', 80),
        make_entry('2025-01-15 08:30:03', '1.2.3.4', '10.0.0.5', 443),
        make_entry('2025-01-15 08:30:04', '1.2.3.4', '10.0.0.6', 22),
        make_entry('2025-01-15 08:30:05', '1.2.3.4', '10.0.0.6', 80),
        make_entry('2025-01-15 08:30:06', '1.2.3.4', '10.0.0.6', 443),
    ]
    findings = detect_port_scan(logs, port_threshold=3, window_minutes=2)
    assert len(findings) == 2

def test_distributed_brute_force_fires():
    logs = [
        make_entry(f'2025-01-15 08:30:{i:02d}', f'1.2.3.{i}', '10.0.0.5', 22)
        for i in range(5)
    ]
    findings = detect_distributed_brute_force(
        logs, src_threshold=5, window_minutes=5)
    assert len(findings) == 1
    assert findings[0]['unique_sources'] == 5
    assert findings[0]['total_attempts'] == 5
    assert findings[0]['dst_port'] == 22
    assert findings[0]['username'] == 'root'

def test_distributed_brute_force_ignores_single_source():
    logs = [
        make_entry(f'2025-01-15 08:30:{i:02d}', '1.2.3.4', '10.0.0.5', 22)
        for i in range(20)
    ]
    assert detect_distributed_brute_force(
        logs, src_threshold=5, window_minutes=5) == []

def test_distributed_brute_force_respects_window():
    logs = [
        make_entry(f'2025-01-15 08:{i*7:02d}:00', f'1.2.3.{i}', '10.0.0.5', 22)
        for i in range(5)
    ]
    assert detect_distributed_brute_force(
        logs, src_threshold=5, window_minutes=5) == []

def test_distributed_brute_force_separates_usernames():
    logs = [
        make_entry('2025-01-15 08:30:01', '1.2.3.1', '10.0.0.5', 22, user='root'),
        make_entry('2025-01-15 08:30:02', '1.2.3.2', '10.0.0.5', 22, user='root'),
        make_entry('2025-01-15 08:30:03', '1.2.3.3', '10.0.0.5', 22, user='root'),
        make_entry('2025-01-15 08:30:04', '1.2.3.4', '10.0.0.5', 22, user='admin'),
        make_entry('2025-01-15 08:30:05', '1.2.3.5', '10.0.0.5', 22, user='admin'),
        make_entry('2025-01-15 08:30:06', '1.2.3.6', '10.0.0.5', 22, user='admin'),
    ]
    findings = detect_distributed_brute_force(
        logs, src_threshold=3, window_minutes=5)
    assert len(findings) == 2
    usernames = {f['username'] for f in findings}
    assert usernames == {'root', 'admin'}

def test_off_hours_flags_after_hours_success():
    logs = [
        make_entry('2025-01-15 03:14:22', '1.2.3.4', '10.0.0.5', 22,
                   action='SUCCESS', user='alice'),
    ]
    findings = detect_off_hours_activity(logs, work_start=8, work_end=18)
    assert len(findings) == 1
    assert findings[0]['reason'] == 'after-hours'
    assert findings[0]['username'] == 'alice'

def test_off_hours_ignores_in_hours_success():
    logs = [
        make_entry('2025-01-15 10:30:00', '1.2.3.4', '10.0.0.5', 22,
                   action='SUCCESS', user='alice'),
    ]
    assert detect_off_hours_activity(logs, work_start=8, work_end=18) == []

def test_off_hours_ignores_failed():
    logs = [
        make_entry('2025-01-15 03:14:22', '1.2.3.4', '10.0.0.5', 22,
                   action='FAILED', user='alice'),
    ]
    assert detect_off_hours_activity(logs, work_start=8, work_end=18) == []

def test_off_hours_weekend_with_allowed_days():
    logs = [
        make_entry('2025-01-18 14:00:00', '1.2.3.4', '10.0.0.5', 22,
                   action='SUCCESS', user='alice'),
    ]
    findings = detect_off_hours_activity(
        logs, work_start=8, work_end=18, allowed_days={0, 1, 2, 3, 4})
    assert len(findings) == 1
    assert findings[0]['reason'] == 'weekend'

def test_off_hours_boundary_hours():
    logs = [
        make_entry('2025-01-15 08:00:00', '1.2.3.4', '10.0.0.5', 22,
                   action='SUCCESS', user='a'),
        make_entry('2025-01-15 18:00:00', '1.2.3.5', '10.0.0.5', 22,
                   action='SUCCESS', user='b'),
    ]
    findings = detect_off_hours_activity(logs, work_start=8, work_end=18)
    assert len(findings) == 1
    assert findings[0]['username'] == 'b'

def test_parse_invalid_src_ip_returns_none():
    line = '2025-01-15 08:23:11,999.999.999.999,10.0.0.5,22,FAILED,admin'
    assert parse_log_line(line) is None

def test_parse_invalid_dst_ip_returns_none():
    line = '2025-01-15 08:23:11,192.168.1.10,999.999.999.999,22,FAILED,admin'
    assert parse_log_line(line) is None

def test_parse_invalid_port_returns_none():
    line = '2025-01-15 08:23:11,192.168.1.10,10.0.0.5,99999,FAILED,admin'
    assert parse_log_line(line) is None