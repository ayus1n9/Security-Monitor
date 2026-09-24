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
)

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
    assert inc['stages']['Preparation'] == []  # rolled back

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
    view_incident(inc)  # should not raise
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