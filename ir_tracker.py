import os
import re
import uuid
import json
from datetime import datetime

from utils import load_json, save_json


STAGES = [
    'Preparation',
    'Detection/Analysis',
    'Containment/Eradication/Recovery',
    'Post-Incident',
]
STATUSES = ['open', 'closed']
SEVERITIES = ['low', 'medium', 'high', 'critical']
INCIDENTS_DIR = 'data/incidents'
INCIDENT_ID_PATTERN = re.compile(
    r'^INC-\d{8}-\d{6}-[0-9a-f]{4}$'
)

def is_valid_incident_id(incident_id):
    """
    Validate the format of an incident ID.

    This also prevents user-controlled path components from being
    passed into filesystem paths.
    """
    return (
        isinstance(incident_id, str)
        and INCIDENT_ID_PATTERN.fullmatch(incident_id) is not None
    )


def validate_incident(incident):
    """
    Validate the basic structure of an incident record.

    Returns True when the incident has the expected structure,
    otherwise False.
    """
    if not isinstance(incident, dict):
        return False

    incident_id = incident.get('id')
    if not is_valid_incident_id(incident_id):
        return False

    if not isinstance(incident.get('name'), str):
        return False

    if not isinstance(incident.get('created'), str):
        return False

    stages = incident.get('stages')
    if not isinstance(stages, dict):
        return False

    # Every expected stage must exist and contain a list.
    for stage in STAGES:
        if stage not in stages:
            return False

        if not isinstance(stages[stage], list):
            return False

    return True


def create_incident(name, severity='low', status='open'):
    """
    Create a new incident record, save it to disk, return the dict.
    Validates severity and status; falls back to defaults on invalid input.
    """
    if severity not in SEVERITIES:
        print(f"[warn] Invalid severity {severity!r}; using 'low'")
        severity = 'low'
    if status not in STATUSES:
        print(f"[warn] Invalid status {status!r}; using 'open'")
        status = 'open'

    now = datetime.now()
    suffix = uuid.uuid4().hex[:4]
    incident_id = f"INC-{now.strftime('%Y%m%d-%H%M%S')}-{suffix}"

    incident = {
        'id': incident_id,
        'name': name,
        'created': now.isoformat(timespec='seconds'),
        'status': status,
        'severity': severity,
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
    Backfills status/severity for old-format incidents (lazy migration).
    Returns None if the file is missing or corrupt.
    """
    path = os.path.join(INCIDENTS_DIR, f"{incident_id}.json")
    if not os.path.exists(path):
        print(f"[warn] Incident not found: {incident_id}")
        return None

    try:
        with open(path, 'r') as f:
            incident = json.load(f)
    except json.JSONDecodeError:
        print(f"[warn] Corrupt incident file: {path}")
        return None

    incident.setdefault('status', 'open')
    incident.setdefault('severity', 'low')
    return incident


def save_incident(incident):
    """
    Write an incident dict back to its JSON file.

    Returns True on success, False on validation or save failure.
    """
    if not validate_incident(incident):
        print("[warn] Cannot save invalid incident data.")
        return False

    incident_id = incident['id']

    path = os.path.join(
        INCIDENTS_DIR,
        f"{incident_id}.json"
    )

    return save_json(path, incident)


def add_action(incident, stage, action, notes=""):
    """
    Append a timestamped action to a stage of the incident,
    then save it.

    Returns True on success, False on invalid input or save failure.
    """
    if not validate_incident(incident):
        print("[warn] Cannot modify invalid incident data.")
        return False

    if stage not in STAGES:
        print(
            f"[warn] Invalid stage: {stage!r}. "
            f"Must be one of: {', '.join(STAGES)}"
        )
        return False

    if not isinstance(action, str):
        print("[warn] Action must be a string.")
        return False

    action = action.strip()

    if not action:
        print("[warn] Action cannot be empty.")
        return False

    if not isinstance(notes, str):
        print("[warn] Notes must be a string.")
        return False

    notes = notes.strip()

    entry = {
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'action': action,
        'notes': notes,
    }

    incident['stages'][stage].append(entry)

    if not save_incident(incident):
        # Roll back the in-memory change if persistence fails.
        incident['stages'][stage].pop()
        return False

    return True


def view_incident(incident):
    """
    Pretty-print an incident's timeline,
    with stages displayed in lifecycle order.
    """
    if incident is None:
        print("[warn] No incident to view.")
        return

    if not isinstance(incident, dict):
        print("[warn] Invalid incident data.")
        return

    def fmt_ts(iso_str):
        try:
            return datetime.fromisoformat(iso_str).strftime(
                '%Y-%m-%d %H:%M:%S'
            )
        except (ValueError, TypeError):
            return str(iso_str)

    print('=' * 70)
    print(f"  Incident: {incident.get('id', '?')}  —  {incident.get('name', '(unnamed)')}")
    print(f"  Created : {fmt_ts(incident.get('created', ''))}")
    print(f"  Status  : {incident.get('status', 'open').upper()}")
    print(f"  Severity: {incident.get('severity', 'low').upper()}")
    print('=' * 70)

    stages = incident.get('stages', {})

    for stage in STAGES:
        entries = stages.get(stage, [])

        if not isinstance(entries, list):
            entries = []

        print(f"\n[{stage}]  ({len(entries)} entries)")
        print('-' * 70)

        if not entries:
            print("  (no actions logged)")
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                print("  [invalid action entry]")
                continue

            timestamp = fmt_ts(entry.get('timestamp', ''))
            action = entry.get('action', '(no action)')

            print(f"  {timestamp}  {action}")

            notes = entry.get('notes', '')

            if notes:
                print(f"      └─ {notes}")

    total = sum(
        len(stages.get(stage, []))
        if isinstance(stages.get(stage, []), list)
        else 0
        for stage in STAGES
    )

    print('\n' + '=' * 70)
    print(f"  TOTAL ACTIONS LOGGED: {total}")
    print('=' * 70)


def list_incidents():
    """
    Return a list of incident summaries sorted newest-first.

    Invalid, corrupt, or malformed incident files are skipped.
    """
    if not os.path.isdir(INCIDENTS_DIR):
        return []

    summaries = []

    try:
        filenames = os.listdir(INCIDENTS_DIR)
    except OSError as e:
        print(f"[warn] Failed to list incidents: {e}")
        return []

    for filename in filenames:
        if not filename.endswith('.json'):
            continue

        incident_id = filename[:-len('.json')]
        incident = load_incident(incident_id)

        if incident is None:
            continue

        stages = incident.get('stages', {})

        stage_counts = {
            stage: (
                len(stages.get(stage, []))
                if isinstance(stages.get(stage, []), list)
                else 0
            )
            for stage in STAGES
        }

        total_actions = sum(stage_counts.values())

        summaries.append({
            'id': incident.get('id', incident_id),
            'name': incident.get('name', '(unnamed)'),
            'created': incident.get('created', ''),
            'status': incident.get('status', 'open'),
            'severity': incident.get('severity', 'low'),
            'total_actions': total_actions,
            'stage_counts': stage_counts,
        })

    summaries.sort(
        key=lambda incident: incident['created'],
        reverse=True
    )

    return summaries


def ir_menu():
    """
    Interactive incident-response tracker menu.

    Returns when the user chooses Exit, presses Ctrl+C,
    or sends EOF.
    """
    current = None

    print("\n=== IR TRACKER ===")

    try:
        while True:
            print()

            if current:
                print(f"Current incident: {current['id']} — {current['name']}")
                print(f"  Status: {current.get('status', 'open').upper()}  "
                    f"Severity: {current.get('severity', 'low').upper()}")
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

                for summary in incidents:
                    print(
                        f"  {summary['id']}  "
                        f"{summary['name']}  "
                        f"(actions={summary['total_actions']})"
                    )

            elif choice == '2':
                name = input("Incident name: ").strip()

                if not name:
                    print("  [warn] Name cannot be empty.")
                    continue

                created = create_incident(name)

                if created is None:
                    print("  [warn] Failed to create incident.")
                    continue

                current = created
                print(f"  Created {current['id']}")

            elif choice == '3':
                incident_id = input("Incident ID: ").strip()

                loaded = load_incident(incident_id)

                if loaded is not None:
                    current = loaded
                    print(f"  Loaded {current['id']}")

            elif choice == '4':
                if current is None:
                    print(
                        "  [warn] "
                        "Load or create an incident first."
                    )
                    continue

                print("  Stages:")

                for index, stage in enumerate(STAGES, start=1):
                    print(f"    {index}. {stage}")

                stage_choice = input(
                    "  Stage number: "
                ).strip()

                try:
                    stage_index = int(stage_choice) - 1

                    if (
                        stage_index < 0
                        or stage_index >= len(STAGES)
                    ):
                        raise ValueError

                except ValueError:
                    print("  [warn] Invalid stage number.")
                    continue

                stage = STAGES[stage_index]

                action = input("  Action: ").strip()

                if not action:
                    print("  [warn] Action cannot be empty.")
                    continue

                notes = input(
                    "  Notes (optional): "
                ).strip()

                if add_action(
                    current,
                    stage,
                    action,
                    notes
                ):
                    print(f"  Logged to {stage}")

            elif choice == '5':
                if current is None:
                    print("  [warn] No incident loaded.")
                    continue

                view_incident(current)

            elif choice == '6':
                print("  Exiting IR tracker.")
                return

            else:
                print("  [warn] Unknown choice.")

    except (KeyboardInterrupt, EOFError):
        print("\n  [interrupted] Exiting IR tracker.")
        return

SEVERITY_RANK = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}


def _auto_severity(findings):
    """
    Assign an incident severity from the findings dict.
    Highest tier wins. Returns one of 'low','medium','high','critical'.
    """
    severity = 'low'

    def escalate(new_level):
        nonlocal severity
        if SEVERITY_RANK[new_level] > SEVERITY_RANK[severity]:
            severity = new_level

    if findings.get('distributed_bf'):
        escalate('critical')
    if findings.get('port_scan'):
        escalate('critical')
    if findings.get('brute_force'):
        escalate('high')
    if findings.get('off_hours'):
        escalate('high')
    if findings.get('unusual_ports'):
        escalate('medium')
    if findings.get('bad_ips'):
        escalate('medium')

    return severity


def _summarize_brute_force(items):
    parts = []
    for f in items[:3]:
        parts.append(f"{f['src_ip']} user={f['username']} attempts={f['count']}")
    tail = ' ...' if len(items) > 3 else ''
    return f"Brute force: {len(items)} source(s) — " + '; '.join(parts) + tail


def _summarize_distributed_bf(items):
    parts = []
    for f in items[:3]:
        parts.append(f"{f['dst_ip']}:{f['dst_port']} user={f['username']} "
                     f"sources={f['unique_sources']}")
    tail = ' ...' if len(items) > 3 else ''
    return f"Distributed brute force: {len(items)} target(s) — " + '; '.join(parts) + tail


def _summarize_port_scan(items):
    parts = []
    for f in items[:3]:
        parts.append(f"{f['src_ip']} -> {f['dst_ip']} ({f['unique_ports']} ports)")
    tail = ' ...' if len(items) > 3 else ''
    return f"Port scan(s): {len(items)} — " + '; '.join(parts) + tail


def _summarize_unusual_ports(items):
    parts = []
    for f in items[:3]:
        parts.append(f"{f['src_ip']} -> {f['dst_ip']}:{f['dst_port']}")
    tail = ' ...' if len(items) > 3 else ''
    return f"Unusual ports: {len(items)} flow(s) — " + '; '.join(parts) + tail


def _summarize_off_hours(items):
    parts = []
    for f in items[:3]:
        parts.append(f"{f['username']}@{f['src_ip']} ({f['reason']})")
    tail = ' ...' if len(items) > 3 else ''
    return f"Off-hours logins: {len(items)} — " + '; '.join(parts) + tail


def _summarize_bad_ips(items):
    srcs = sorted({f['matched_ip'] for f in items})
    return (f"Blocklist hits: {len(items)} event(s) from "
            + ', '.join(srcs[:5])
            + (' ...' if len(srcs) > 5 else ''))


_SUMMARIZERS = [
    ('distributed_bf', _summarize_distributed_bf),
    ('port_scan',      _summarize_port_scan),
    ('brute_force',    _summarize_brute_force),
    ('off_hours',      _summarize_off_hours),
    ('unusual_ports',  _summarize_unusual_ports),
    ('bad_ips',        _summarize_bad_ips),
]


def create_incident_from_findings(findings, name, severity=None):
    """
    Create an IR incident pre-populated with a summary action per
    detection category. Severity is auto-assigned from findings unless
    overridden.
    Returns the incident dict.
    """
    if severity is None:
        severity = _auto_severity(findings)

    incident = create_incident(name, severity=severity, status='open')

    for key, summarizer in _SUMMARIZERS:
        items = findings.get(key) or []
        if not items:
            continue
        add_action(incident, 'Detection/Analysis', summarizer(items))

    return incident

if __name__ == '__main__':
    ir_menu()