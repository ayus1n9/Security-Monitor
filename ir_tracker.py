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

if __name__ == '__main__':
    print("\n=== save_incident ===")
    inc = create_incident("Save test")
    inc['stages']['Preparation'].append({
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'action': 'Ran IR tabletop exercise',
        'notes': 'Quarterly drill',
    })
    ok = save_incident(inc)
    print(f"Save returned: {ok}")
    reloaded = load_incident(inc['id'])
    print("Reloaded Preparation stage entries:",
          len(reloaded['stages']['Preparation']))
    print("First action:", reloaded['stages']['Preparation'][0]['action'])
    print("\nNo-id case:")
    print("Save returned:", save_incident({'name': 'no id'}))

def ir_menu():
    print("[stub] IR tracker coming in Phase 2.")