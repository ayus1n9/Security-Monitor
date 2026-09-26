"""
Tests for watch_log — the tail-follow monitor.
"""

import os
import threading
import time
import pytest

from sentinelog.log_analyzer import watch_log

def _write(tmp_path, lines):
    path = tmp_path / "test.log"
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    return str(path)


def test_watch_detects_brute_force_from_start(tmp_path, capsys):
    lines = [
        f'2025-01-15 08:30:{i:02d},1.2.3.4,10.0.0.5,22,FAILED,root'
        for i in range(6)
    ]
    path = _write(tmp_path, lines)

    watch_log(path, from_start=True, max_ticks=1, poll_interval=0)

    out = capsys.readouterr().out
    assert 'BRUTE FORCE' in out
    assert '1.2.3.4' in out
    assert 'root' in out


def test_watch_detects_unusual_port(tmp_path, capsys):
    lines = [
        '2025-01-15 08:30:00,1.2.3.4,10.0.0.5,31337,FAILED,root',
    ]
    path = _write(tmp_path, lines)

    watch_log(path, from_start=True, max_ticks=1, poll_interval=0,
              allowed_ports={22, 80, 443})

    out = capsys.readouterr().out
    assert 'UNUSUAL PORT' in out
    assert '31337' in out


def test_watch_detects_bad_ip(tmp_path, capsys):
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("203.0.113.5\n")

    lines = [
        '2025-01-15 08:30:00,203.0.113.5,10.0.0.5,22,FAILED,root',
    ]
    path = _write(tmp_path, lines)

    watch_log(path, blocklist_path=str(blocklist_path),
              from_start=True, max_ticks=1, poll_interval=0)

    out = capsys.readouterr().out
    assert 'BLOCKLIST HIT' in out
    assert '203.0.113.5' in out


def test_watch_deduplicates_blocklist_hits(tmp_path, capsys):
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("203.0.113.5\n")

    lines = [
        f'2025-01-15 08:30:{i:02d},203.0.113.5,10.0.0.5,22,FAILED,root'
        for i in range(5)
    ]
    path = _write(tmp_path, lines)

    watch_log(path, blocklist_path=str(blocklist_path), from_start=True, max_ticks=1, poll_interval=0)

    out = capsys.readouterr().out
    assert out.count('BLOCKLIST HIT') == 1


def test_watch_no_alerts_on_clean_log(tmp_path, capsys):
    lines = [
        '2025-01-15 08:30:00,192.168.1.10,10.0.0.5,443,SUCCESS,alice',
        '2025-01-15 08:31:00,192.168.1.10,10.0.0.5,80,SUCCESS,alice',
    ]
    path = _write(tmp_path, lines)

    watch_log(path, from_start=True, max_ticks=1, poll_interval=0)

    out = capsys.readouterr().out
    assert 'BRUTE FORCE' not in out
    assert 'UNUSUAL PORT' not in out
    assert 'PORT SCAN' not in out

def test_watch_deduplicates_across_ticks(tmp_path, capsys):
    lines = [
        f'2025-01-15 08:30:{i:02d},1.2.3.4,10.0.0.5,22,FAILED,root'
        for i in range(6)
    ]
    path = _write(tmp_path, lines)

    watch_log(path, from_start=True, max_ticks=3, poll_interval=0)

    out = capsys.readouterr().out
    assert out.count('BRUTE FORCE') == 1

def test_watch_detects_appended_brute_force(tmp_path, capsys):
    path = _write(tmp_path, [])

    result = {}

    def run_watch():
        result["seen"] = watch_log(
            path,
            from_start=False,
            max_ticks=100,
            poll_interval=0.01
        )

    thread = threading.Thread(target=run_watch)
    thread.start()

    time.sleep(0.05)

    with open(path, 'a') as f:
        for i in range(6):
            f.write(
                f'2025-01-15 08:30:{i:02d},'
                f'1.2.3.4,10.0.0.5,22,FAILED,root\n'
            )

    thread.join(timeout=2)

    assert not thread.is_alive()

    out = capsys.readouterr().out
    assert 'BRUTE FORCE' in out
    assert '1.2.3.4' in out
    assert 'root' in out