"""
Tests for log_analyzer plotting functions.
"""

import os
import pytest
from sentinelog.log_analyzer import plot_login_timeline, plot_port_distribution


def _make_entry(ts, action='FAILED'):
    from datetime import datetime
    return {
        'timestamp': datetime.strptime(ts, '%Y-%m-%d %H:%M:%S'),
        'src_ip': '1.2.3.4',
        'dst_ip': '10.0.0.5',
        'dst_port': 22,
        'action': action,
        'username': 'root',
    }


def test_plot_timeline_creates_file(tmp_path):
    logs = [
        _make_entry('2025-01-15 08:30:01'),
        _make_entry('2025-01-15 08:30:14'),
        _make_entry('2025-01-15 08:31:02'),
        _make_entry('2025-01-15 08:32:11'),
    ]
    out = tmp_path / "timeline.png"
    ok = plot_login_timeline(logs, output_path=str(out))
    assert ok is True
    assert out.exists()
    assert out.stat().st_size > 0


def test_plot_timeline_empty_returns_false(tmp_path, capsys):
    out = tmp_path / "timeline.png"
    ok = plot_login_timeline([], output_path=str(out))
    assert ok is False
    assert not out.exists()


def test_plot_timeline_no_failures_returns_false(tmp_path, capsys):
    logs = [_make_entry('2025-01-15 08:30:00', action='SUCCESS')]
    out = tmp_path / "timeline.png"
    ok = plot_login_timeline(logs, output_path=str(out))
    assert ok is False
    assert not out.exists()


def test_plot_timeline_bad_path_returns_false(tmp_path, capsys):
    logs = [_make_entry('2025-01-15 08:30:00')]
    bad_path = str(tmp_path / "nope" / "subdir" / "out.png")
    ok = plot_login_timeline(logs, output_path=bad_path)
    assert ok is False


def _make_port_entry(port):
    return {
        'timestamp': __import__('datetime').datetime(2025, 1, 15, 8, 30, 0),
        'src_ip': '1.2.3.4',
        'dst_ip': '10.0.0.5',
        'dst_port': port,
        'action': 'FAILED',
        'username': 'root',
    }


def test_plot_ports_creates_file(tmp_path):
    logs = (
        [_make_port_entry(22) for _ in range(5)] +
        [_make_port_entry(443) for _ in range(10)] +
        [_make_port_entry(31337)]
    )
    out = tmp_path / "ports.png"
    ok = plot_port_distribution(logs, output_path=str(out))
    assert ok is True
    assert out.exists()
    assert out.stat().st_size > 0


def test_plot_ports_empty_returns_false(tmp_path):
    out = tmp_path / "ports.png"
    assert plot_port_distribution([], output_path=str(out)) is False


def test_plot_ports_groups_other_bucket(tmp_path):
    logs = [_make_port_entry(1000 + i) for i in range(20)]
    out = tmp_path / "ports.png"
    ok = plot_port_distribution(logs, output_path=str(out), top_n=5)
    assert ok is True


def test_plot_ports_bad_path_returns_false(tmp_path):
    logs = [_make_port_entry(80)]
    bad = str(tmp_path / "nope" / "out.png")
    assert plot_port_distribution(logs, output_path=bad) is False

def test_plot_ports_invalid_top_n(tmp_path):
    logs = [_make_port_entry(80)]
    out = tmp_path / "ports.png"

    assert plot_port_distribution(
        logs,
        output_path=str(out),
        top_n=0
    ) is False