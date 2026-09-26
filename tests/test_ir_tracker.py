"""
Unit tests for ir_tracker.py.
Run: python3 -m pytest tests/ -v
"""

import json
import os
import pytest
import ir_tracker
from ir_tracker import (
    STAGES,
    create_incident,
    load_incident,
    save_incident,
    add_action,
    list_incidents,
    view_incident,
    create_incident_from_findings,
    _auto_severity
)
from ir_tracker import link_report_to_incident
from ir_tracker import export_incident_markdown
from ir_tracker import close_incident



@pytest.fixture(autouse=True)
def isolated_incidents_dir(tmp_path, monkeypatch):
    """Redirect INCIDENTS_DIR to a per-test temp directory."""
    monkeypatch.setattr(ir_tracker, 'INCIDENTS_DIR', str(tmp_path))
    return tmp_path

def test_create_incident_shape():
    inc = create_incident("Test incident")
    assert inc['id'].startswith('INC-')
    assert inc['name'] == "Test incident"
    assert 'created' in inc
    assert set(inc['stages'].keys()) == set(STAGES)

def test_create_incident_writes_file(isolated_incidents_dir):
    inc = create_incident("File test")
    path = os.path.join(str(isolated_incidents_dir), f"{inc['id']}.json")
    assert os.path.exists(path)
    with open(path) as f:
        on_disk = json.load(f)
    assert on_disk['id'] == inc['id']
    assert on_disk['name'] == "File test"

def test_create_incident_returns_none_on_save_failure(monkeypatch):
    monkeypatch.setattr(ir_tracker, 'save_json', lambda *args, **kwargs: False)

    incident = create_incident("Save failure")

    assert incident is None

def test_create_incident_stages_in_order():
    """The four stages must be present AND in the guide's order."""
    inc = create_incident("Order test")
    assert list(inc['stages'].keys()) == STAGES

def test_load_round_trip():
    inc = create_incident("Round trip")
    loaded = load_incident(inc['id'])
    assert loaded is not None
    assert loaded['id'] == inc['id']
    assert loaded['name'] == inc['name']

def test_load_missing_returns_none():
    assert load_incident('INC-19000101-000000') is None

def test_load_corrupt_returns_none(isolated_incidents_dir):
    bad_path = os.path.join(str(isolated_incidents_dir), 'INC-BAD-1.json')
    with open(bad_path, 'w') as f:
        f.write('{not valid json')
    assert load_incident('INC-BAD-1') is None

def test_add_action_success():
    inc = create_incident("Add action")
    ok = add_action(inc, 'Preparation', 'Ran tabletop drill', notes='Q4')
    assert ok is True
    assert len(inc['stages']['Preparation']) == 1
    entry = inc['stages']['Preparation'][0]
    assert entry['action'] == 'Ran tabletop drill'
    assert entry['notes'] == 'Q4'
    assert 'timestamp' in entry

def test_add_action_persists():
    inc = create_incident("Persist test")
    add_action(inc, 'Detection/Analysis', 'Confirmed brute force')
    reloaded = load_incident(inc['id'])
    assert len(reloaded['stages']['Detection/Analysis']) == 1
    assert reloaded['stages']['Detection/Analysis'][0]['action'] == 'Confirmed brute force'

def test_add_action_invalid_stage_rejected():
    inc = create_incident("Bad stage")
    ok = add_action(inc, 'Bogus Stage', 'should not land')
    assert ok is False
    for stage in STAGES:
        assert inc['stages'][stage] == []

def test_add_action_rolls_back_on_save_failure(monkeypatch):
    inc = create_incident("Rollback test")

    def failing_save(_):
        return False
    monkeypatch.setattr(ir_tracker, 'save_incident', failing_save)

    ok = add_action(inc, 'Preparation', 'should roll back')
    assert ok is False
    assert inc['stages']['Preparation'] == []

def test_list_empty_returns_empty_list():
    assert list_incidents() == []

def test_list_returns_summaries():
    inc1 = create_incident("First")
    inc2 = create_incident("Second")
    add_action(inc1, 'Preparation', 'prep action')
    add_action(inc1, 'Detection/Analysis', 'detect action')
    add_action(inc2, 'Preparation', 'only prep')

    summaries = list_incidents()
    assert len(summaries) == 2

    by_id = {s['id']: s for s in summaries}
    assert by_id[inc1['id']]['total_actions'] == 2
    assert by_id[inc1['id']]['stage_counts']['Preparation'] == 1
    assert by_id[inc1['id']]['stage_counts']['Detection/Analysis'] == 1
    assert by_id[inc2['id']]['total_actions'] == 1

def test_view_does_not_crash_empty(capsys):
    inc = create_incident("Empty view")
    view_incident(inc)
    out = capsys.readouterr().out
    assert inc['id'] in out
    assert 'TOTAL ACTIONS LOGGED: 0' in out

def test_view_does_not_crash_none(capsys):
    view_incident(None)
    out = capsys.readouterr().out
    assert 'No incident to view' in out

def test_view_shows_entries(capsys):
    inc = create_incident("Populated")
    add_action(inc, 'Preparation', 'Step one')
    add_action(inc, 'Post-Incident', 'Lessons learned scheduled')
    view_incident(inc)
    out = capsys.readouterr().out
    assert 'Step one' in out
    assert 'Lessons learned scheduled' in out
    assert 'TOTAL ACTIONS LOGGED: 2' in out

def test_create_incident_default_metadata():
    inc = create_incident("Defaults test")
    assert inc['status'] == 'open'
    assert inc['severity'] == 'low'


def test_create_incident_custom_severity():
    inc = create_incident("Critical case", severity='critical')
    assert inc['severity'] == 'critical'
    assert inc['status'] == 'open'


def test_create_incident_invalid_severity_falls_back():
    inc = create_incident("Bad severity", severity='emergency')
    assert inc['severity'] == 'low'


def test_load_migrates_old_incident(isolated_incidents_dir):
    old = {
        'id': 'INC-20250101-100000-abcd',
        'name': 'Legacy incident',
        'created': '2025-01-01T10:00:00',
        'stages': {s: [] for s in STAGES},
    }
    path = os.path.join(str(isolated_incidents_dir), 'INC-20250101-100000-abcd.json')
    with open(path, 'w') as f:
        json.dump(old, f)

    loaded = load_incident('INC-20250101-100000-abcd')
    assert loaded is not None
    assert loaded['status'] == 'open'
    assert loaded['severity'] == 'low'
    assert loaded['name'] == 'Legacy incident'


def test_list_includes_metadata():
    create_incident("High case", severity='high')
    summaries = list_incidents()
    assert len(summaries) == 1
    assert summaries[0]['severity'] == 'high'
    assert summaries[0]['status'] == 'open'


def test_auto_severity_critical_on_port_scan():
    findings = {'port_scan': [{'src_ip': '1.1.1.1'}]}
    assert _auto_severity(findings) == 'critical'


def test_auto_severity_high_on_brute_force():
    findings = {'brute_force': [{'src_ip': '1.1.1.1'}]}
    assert _auto_severity(findings) == 'high'


def test_auto_severity_medium_on_bad_ips_only():
    findings = {'bad_ips': [{'matched_ip': '2.2.2.2'}]}
    assert _auto_severity(findings) == 'medium'


def test_auto_severity_low_on_empty():
    assert _auto_severity({}) == 'low'


def test_auto_severity_highest_tier_wins():
    findings = {
        'port_scan': [{'src_ip': '1.1.1.1'}],
        'bad_ips': [{'matched_ip': '2.2.2.2'}],
    }
    assert _auto_severity(findings) == 'critical'


def test_create_from_findings_populates_detection_stage():
    findings = {
        'brute_force': [{
            'src_ip': '1.2.3.4', 'username': 'root',
            'count': 7, 'first_seen': None, 'last_seen': None,
            'dst_ports': {22},
        }],
    }
    inc = create_incident_from_findings(findings, "Auto incident")
    assert inc['severity'] == 'high'
    detection_entries = inc['stages']['Detection/Analysis']
    assert len(detection_entries) == 1
    assert 'Brute force' in detection_entries[0]['action']
    assert '1.2.3.4' in detection_entries[0]['action']


def test_create_from_findings_empty_creates_low_no_actions():
    inc = create_incident_from_findings({}, "Nothing found")
    assert inc['severity'] == 'low'
    for stage in STAGES:
        assert inc['stages'][stage] == []


def test_link_report_copies_and_logs(isolated_incidents_dir):
    inc = create_incident("Link test")

    report_path = os.path.join(str(isolated_incidents_dir), 'sample_report.txt')
    with open(report_path, 'w') as f:
        f.write("FAKE REPORT CONTENT")

    ok = link_report_to_incident(inc, report_path)
    assert ok is True

    prep = inc['stages']['Preparation']
    assert len(prep) == 1
    assert 'Attached evidence' in prep[0]['action']

    evidence_dir = os.path.join(str(isolated_incidents_dir), f"{inc['id']}_evidence")
    assert os.path.isdir(evidence_dir)
    copied = os.listdir(evidence_dir)
    assert len(copied) == 1
    assert copied[0].endswith('sample_report.txt')


def test_link_report_missing_file_returns_false(isolated_incidents_dir):
    inc = create_incident("Missing report")
    ok = link_report_to_incident(inc, 'nonexistent.txt')
    assert ok is False
    assert inc['stages']['Preparation'] == []


def test_link_report_no_id_returns_false():
    ok = link_report_to_incident({'name': 'no id'}, 'whatever.txt')
    assert ok is False


def test_link_report_none_incident_returns_false():
    ok = link_report_to_incident(None, 'whatever.txt')
    assert ok is False

def test_load_rejects_path_traversal():
    assert load_incident('../../evil') is None

def test_load_rejects_invalid_incident_id():
    assert load_incident('INC-BAD-1') is None

def test_load_invalid_structure_returns_none(isolated_incidents_dir):
    incident_id = 'INC-20260925-120000-abcd'

    path = os.path.join(
        str(isolated_incidents_dir),
        f'{incident_id}.json'
    )

    with open(path, 'w') as f:
        json.dump({
            'id': incident_id,
            'name': 123,
            'created': '2026-09-25T12:00:00',
            'stages': {}
        }, f)

    assert load_incident(incident_id) is None


def test_export_markdown_creates_file(isolated_incidents_dir):
    inc = create_incident("Markdown export test", severity='high')
    add_action(inc, 'Preparation', 'Baseline audit', notes='v4.2.1')
    add_action(inc, 'Detection/Analysis', 'Detected brute force')

    md_path = os.path.join(str(isolated_incidents_dir), 'test.md')
    ok = export_incident_markdown(inc, output_path=md_path)
    assert ok is True
    assert os.path.exists(md_path)

    content = open(md_path).read()
    assert inc['id'] in content
    assert 'Markdown export test' in content
    assert '**HIGH**' in content
    assert 'Baseline audit' in content
    assert 'v4.2.1' in content
    assert 'Detected brute force' in content
    assert '## Preparation' in content
    assert '## Detection/Analysis' in content
    assert '## Containment/Eradication/Recovery' in content
    assert '## Post-Incident' in content
    assert '_No actions logged._' in content
    assert 'Total actions logged: 2' in content


def test_export_markdown_default_path(isolated_incidents_dir):
    inc = create_incident("Default path test")
    ok = export_incident_markdown(inc)
    assert ok is True
    expected = os.path.join(str(isolated_incidents_dir), f"{inc['id']}.md")
    assert os.path.exists(expected)


def test_export_markdown_no_id_returns_false():
    assert export_incident_markdown({'name': 'no id'}) is False


def test_export_markdown_none_returns_false():
    assert export_incident_markdown(None) is False

def test_create_from_findings_returns_none_on_save_failure(monkeypatch):
    monkeypatch.setattr(ir_tracker, 'save_json', lambda *a, **k: False)
    result = create_incident_from_findings({'brute_force': [{'src_ip': '1.1.1.1', 'username': 'r', 'count': 5, 'first_seen': None, 'last_seen': None, 'dst_ports': {22}}]}, "Should fail")
    assert result is None


def test_close_incident_success():
    inc = create_incident("To close", severity='medium')
    ok = close_incident(inc, "Attacker blocked; no exfil")
    assert ok is True
    assert inc['status'] == 'closed'
    post = inc['stages']['Post-Incident']
    assert len(post) == 1
    assert 'Incident closed' in post[0]['action']
    assert 'no exfil' in post[0]['action']


def test_close_incident_updates_severity():
    inc = create_incident("Severity change", severity='low')
    ok = close_incident(inc, "Escalated", severity='critical')
    assert ok is True
    assert inc['severity'] == 'critical'
    assert inc['status'] == 'closed'


def test_close_incident_rejects_already_closed():
    inc = create_incident("Double close")
    assert close_incident(inc, "first close") is True
    assert close_incident(inc, "second close") is False
    assert len(inc['stages']['Post-Incident']) == 1


def test_close_incident_rejects_empty_summary():
    inc = create_incident("Empty summary")
    assert close_incident(inc, "") is False
    assert close_incident(inc, "   ") is False
    assert inc['status'] == 'open'


def test_close_incident_rejects_none():
    assert close_incident(None, "whatever") is False


def test_close_incident_persists():
    inc = create_incident("Persist close")
    close_incident(inc, "done")
    reloaded = load_incident(inc['id'])
    assert reloaded['status'] == 'closed'
    assert len(reloaded['stages']['Post-Incident']) == 1


def test_close_incident_rolls_back_on_save_failure(monkeypatch):
    inc = create_incident("Rollback close", severity='high')
    original_sev = inc['severity']

    def failing_save(_):
        return False
    monkeypatch.setattr(ir_tracker, 'save_incident', failing_save)

    ok = close_incident(inc, "should roll back", severity='low')
    assert ok is False
    assert inc['status'] == 'open'
    assert inc['severity'] == original_sev
    assert inc['stages']['Post-Incident'] == []