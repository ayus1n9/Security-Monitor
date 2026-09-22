import json
import os
from datetime import datetime

STAGES = [
    'Preparation',
    'Detection/Analysis',
    'Containment/Eradication/Recovery',
    'Post-Incident',
]

INCIDENTS_DIR = 'data/incidents'

def create_incident(name):
    """
    Create a new incident record, save it to disk, return the dict.
    """
    now = datetime.now()
    incident_id = f"INC-{now.strftime('%Y%m%d-%H%M%S')}"

    incident = {
        'id': incident_id,
        'name': name,
        'created': now.isoformat(timespec='seconds'),
        'stages': {stage: [] for stage in STAGES},
    }

    os.makedirs(INCIDENTS_DIR, exist_ok=True)
    path = os.path.join(INCIDENTS_DIR, f"{incident_id}.json")
    with open(path, 'w') as f:
        json.dump(incident, f, indent=2, ensure_ascii=False)

    return incident

def load_incident(incident_id):
    """
    Load an incident from disk by ID.
    Returns None if the file is missing or corrupt.
    """
    path = os.path.join(INCIDENTS_DIR, f"{incident_id}.json")
    if not os.path.exists(path):
        print(f"[warn] Incident not found: {incident_id}")
        return None

    try:
        with open(path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"[warn] Corrupt incident file: {path}")
        return None

def save_incident(incident):
    """
    Write an incident dict back to its JSON file.
    Returns True on success, False on failure.
    """
    incident_id = incident.get('id')
    if not incident_id:
        print("[warn] Cannot save incident without an 'id'")
        return False

    path = os.path.join(INCIDENTS_DIR, f"{incident_id}.json")
    try:
        os.makedirs(INCIDENTS_DIR, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(incident, f, indent=2, ensure_ascii=False)
        return True
    except OSError as e:
        print(f"[warn] Failed to save incident {incident_id}: {e}")
        return False

def add_action(incident, stage, action, notes=""):
    """
    Append a timestamped action to a stage of the incident, then save.
    Returns True on success, False on invalid stage or save failure.
    """
    if stage not in STAGES:
        print(f"[warn] Invalid stage: {stage!r}. "
              f"Must be one of: {', '.join(STAGES)}")
        return False
    entry = {
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'action': action,
        'notes': notes,
    }
    incident['stages'][stage].append(entry)

    if not save_incident(incident):
        incident['stages'][stage].pop()
        return False

    return True


if __name__ == '__main__':
    print("\n=== add_action ===")
    inc = create_incident("Brute Force Response")
    ok = add_action(inc, 'Preparation', 'Verified firewall ruleset version', notes='Baseline audit before response.')
    print("Prep add:", ok)
    ok = add_action(inc, 'Detection/Analysis', 'Confirmed 7 failed SSH logins from 203.0.113.5')
    print("Detection add:", ok)
    ok = add_action(inc, 'Bogus Stage', 'should fail')
    print("Bad stage add:", ok)
    reloaded = load_incident(inc['id'])
    for stage in STAGES:
        entries = reloaded['stages'][stage]
        print(f"{stage}: {len(entries)} entries")
        for e in entries:
            print(f"  [{e['timestamp']}] {e['action']}")

def ir_menu():
    print("[stub] IR tracker coming in Phase 2.")