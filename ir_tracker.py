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
    except (OSError, TypeError) as e:
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

def ir_menu():
    """
    Interactive IR tracker menu. Returns when user chooses Exit.
    """
    current = None
    print("\n=== IR TRACKER ===")
    try:
        while True:
            print()
            if current:
                print(f"Current incident: {current['id']} — {current['name']}")
            else:
                print("Current incident: (none loaded)")
            print("  1. List all incidents")
            print("  2. Create new incident")
            print("  3. Load an incident by ID")
            print("  4. Add action to current incident")
            print("  5. View current incident")
            print("  6. Exit")
            choice = input("Choice: ").strip()
            if choice == '1':
                incidents = list_incidents()
                if not incidents:
                    print("  (no incidents yet)")
                    continue
                for s in incidents:
                    print(f"  {s['id']}  {s['name']}  "
                        f"(actions={s['total_actions']})")
            elif choice == '2':
                name = input("Incident name: ").strip()
                if not name:
                    print("  [warn] Name cannot be empty.")
                    continue
                current = create_incident(name)
                print(f"  Created {current['id']}")
            elif choice == '3':
                incident_id = input("Incident ID: ").strip()
                loaded = load_incident(incident_id)
                if loaded:
                    current = loaded
                    print(f"  Loaded {current['id']}")
            elif choice == '4':
                if not current:
                    print("  [warn] Load or create an incident first.")
                    continue
                print("  Stages:")
                for i, stage in enumerate(STAGES, start=1):
                    print(f"    {i}. {stage}")
                stage_choice = input("  Stage number: ").strip()
                try:
                    stage_idx = int(stage_choice) - 1
                    if stage_idx < 0 or stage_idx >= len(STAGES):
                        raise ValueError
                except ValueError:
                    print("  [warn] Invalid stage number.")
                    continue
                stage = STAGES[stage_idx]
                action = input("  Action: ").strip()
                if not action:
                    print("  [warn] Action cannot be empty.")
                    continue
                notes = input("  Notes (optional): ").strip()
                if add_action(current, stage, action, notes):
                    print(f"  Logged to {stage}")
            elif choice == '5':
                if not current:
                    print("  [warn] No incident loaded.")
                    continue
                view_incident(current)
            elif choice == '6':
                print("  Exiting IR tracker.")
                return
            else:
                print("  [warn] Unknown choice.")
            pass
        
    except:
        print("\n  [interrupted] Exiting IR tracker.")
        return

if __name__ == '__main__':
    ir_menu()