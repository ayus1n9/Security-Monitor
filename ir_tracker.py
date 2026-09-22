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

def view_incident(incident):
    """
    Pretty-print an incident's timeline, stages in lifecycle order.
    """
    if incident is None:
        print("[warn] No incident to view.")
        return
    def fmt_ts(iso_str):
        try:
            return datetime.fromisoformat(iso_str).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            return str(iso_str)
    print('=' * 70)
    print(f"  Incident: {incident.get('id', '?')}  —  {incident.get('name', '(unnamed)')}")
    print(f"  Created : {fmt_ts(incident.get('created', ''))}")
    print('=' * 70)
    for stage in STAGES:
        entries = incident.get('stages', {}).get(stage, [])
        print(f"\n[{stage}]  ({len(entries)} entries)")
        print('-' * 70)
        if not entries:
            print("  (no actions logged)")
            continue
        for e in entries:
            ts = fmt_ts(e.get('timestamp', ''))
            action = e.get('action', '(no action)')
            print(f"  {ts}  {action}")

            notes = e.get('notes', '')
            if notes:
                print(f"      └─ {notes}")

    total = sum(len(incident.get('stages', {}).get(s, [])) for s in STAGES)
    print('\n' + '=' * 70)
    print(f"  TOTAL ACTIONS LOGGED: {total}")
    print('=' * 70)

def list_incidents():
    """
    Return a list of incident summaries sorted newest-first.
    Skips unreadable/corrupt files.
    """
    if not os.path.isdir(INCIDENTS_DIR):
        return []
    summaries = []
    for filename in os.listdir(INCIDENTS_DIR):
        if not filename.endswith('.json'):
            continue
        incident_id = filename[:-len('.json')]
        incident = load_incident(incident_id)
        if incident is None:
            continue
        stages = incident.get('stages', {})
        stage_counts = {s: len(stages.get(s, [])) for s in STAGES}
        total_actions = sum(stage_counts.values())
        summaries.append({
            'id': incident.get('id', incident_id),
            'name': incident.get('name', '(unnamed)'),
            'created': incident.get('created', ''),
            'total_actions': total_actions,
            'stage_counts': stage_counts,
        })
    summaries.sort(key=lambda s: s['created'], reverse=True)
    return summaries


if __name__ == '__main__':
    print("\n=== list_incidents ===")
    incidents = list_incidents()
    print(f"Found {len(incidents)} incident(s):")
    for s in incidents:
        print(f"  {s['id']}  {s['name']}")
        print(f"    created: {s['created']}  "
              f"total actions: {s['total_actions']}")
        counts = ', '.join(
            f"{stage.split('/')[0]}={s['stage_counts'][stage]}"
            for stage in STAGES
        )
        print(f"    {counts}")

def ir_menu():
    print("[stub] IR tracker coming in Phase 2.")