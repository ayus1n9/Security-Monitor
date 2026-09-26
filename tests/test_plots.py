"""
Tests for log_analyzer plotting functions.
"""

import os

import pytest

from log_analyzer import plot_login_timeline


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