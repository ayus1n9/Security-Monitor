import json
import os
import shutil
import uuid
import re
from datetime import datetime
from . import utils
from .utils import load_json, save_json
from datetime import datetime, timedelta


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

    if incident.get('status') not in STATUSES:
        return False

    if incident.get('severity') not in SEVERITIES:
        return False

    stages = incident.get('stages')
    if not isinstance(stages, dict):
        return False
    
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

    path = os.path.join(
        INCIDENTS_DIR,
        f"{incident_id}.json"
    )

    if not save_json(path, incident):
        print(f"[warn] Failed to save incident: {incident_id}")
        return None

    return incident


def load_incident(incident_id):
    """
    Load an incident from disk by ID.
    Backfills status/severity for old-format incidents (lazy migration).
    Returns None if the file is missing or corrupt.
    """
    if not is_valid_incident_id(incident_id):
        print(f"[warn] Invalid incident ID: {incident_id!r}")
        return None

    path = os.path.join(INCIDENTS_DIR, f"{incident_id}.json")

    if not os.path.exists(path):
        print(f"[warn] Incident not found: {incident_id}")
        return None

    try:
        with open(path, 'r', encoding='utf-8') as f:
            incident = json.load(f)
    except FileNotFoundError:
        print(f"[warn] Incident not found: {incident_id}")
        return None
    except json.JSONDecodeError:
        print(f"[warn] Corrupt incident file: {path}")
        return None
    except (OSError, UnicodeError) as e:
        print(f"[warn] Failed to read incident: {e}")
        return None

    incident.setdefault('status', 'open')
    incident.setdefault('severity', 'low')

    if not validate_incident(incident):
        print(f"[warn] Invalid incident structure: {incident_id!r}")
        return None

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
            'closed_at': incident.get('closed_at'),
        })

    summaries.sort(
        key=lambda incident: incident['created'],
        reverse=True
    )

    return summaries

def _menu_list():
    """Option 1: list all incidents."""
    incidents = list_incidents()
    if not incidents:
        print("  (no incidents yet)")
        return
    for s in incidents:
        print(f"  {s['id']}  {s['name']}  "
              f"[{s['status']}/{s['severity']}]  "
              f"(actions={s['total_actions']})")


def _menu_dashboard():
    """Option 6: print aggregate stats."""
    stats = dashboard_stats()
    print()
    print(f"  Total incidents : {stats['total']}")
    print(f"  Open / Closed   : {stats['by_status']['open']} / "
          f"{stats['by_status']['closed']}")
    bs = stats['by_severity']
    print(f"  By severity     : low={bs['low']} med={bs['medium']} "
          f"high={bs['high']} crit={bs['critical']}")
    obs = stats['open_by_severity']
    print(f"  Open by severity: low={obs['low']} med={obs['medium']} "
          f"high={obs['high']} crit={obs['critical']}")
    print(f"  New in last 7d  : {stats['new_last_7_days']}")
    if stats['oldest_open']:
        oo = stats['oldest_open']
        print(f"  Oldest open     : {oo['id']} — {oo['name']} "
              f"({oo['age_days']} days)")
    else:
        print("  Oldest open     : (none)")
    print(f"  Mean open age   : {stats['mean_open_age_days']} days")


def _menu_search():
    """Option 7: search incidents by text."""
    query = input("Search query: ").strip()
    if not query:
        print("  [warn] Query cannot be empty.")
        return

    cs_raw = input("Case sensitive? [y/N]: ").strip().lower()
    case_sensitive = cs_raw in ('y', 'yes')

    results = search_incidents(query, case_sensitive=case_sensitive)
    if not results:
        print("  (no matches)")
        return

    for r in results:
        print(f"  {r['id']}  {r['name']}  "
              f"[{r['status']}/{r['severity']}]  "
              f"({len(r['matches'])} match(es))")


def _menu_filter():
    """Option 8: filter incidents by metadata."""
    status = input("Status (open/closed/blank): ").strip() or None
    severity = input("Severity (low/medium/high/critical/blank): ").strip() or None
    since = input("Since (ISO date or blank): ").strip() or None
    until = input("Until (ISO date or blank): ").strip() or None

    kwargs = {}
    if status is not None:
        kwargs['status'] = status
    if severity is not None:
        kwargs['severity'] = severity
    if since is not None:
        kwargs['since'] = since
    if until is not None:
        kwargs['until'] = until

    results = filter_incidents(**kwargs)
    if not results:
        print("  (no matches)")
        return

    for s in results:
        print(f"  {s['id']}  {s['name']}  "
              f"[{s['status']}/{s['severity']}]  "
              f"(actions={s['total_actions']})")


def _prompt_stage():
    """Prompt for a stage number (1-4). Returns stage name or None."""
    print("  Stages:")
    for i, stage in enumerate(STAGES, start=1):
        print(f"    {i}. {stage}")
    raw = input("  Stage number: ").strip()
    try:
        idx = int(raw) - 1
        if idx < 0 or idx >= len(STAGES):
            raise ValueError
    except ValueError:
        print("  [warn] Invalid stage number.")
        return None
    return STAGES[idx]


def _menu_add_action(current):
    """Option 4: append an action to a stage."""
    stage = _prompt_stage()
    if stage is None:
        return

    action = input("  Action: ").strip()
    if not action:
        print("  [warn] Action cannot be empty.")
        return

    notes = input("  Notes (optional): ").strip()
    if add_action(current, stage, action, notes):
        print(f"  Logged to {stage}")


def _menu_add_evidence(current):
    """Option 9: attach evidence to a stage."""
    stage = _prompt_stage()
    if stage is None:
        return

    etype = input("  Evidence type (e.g., pcap, screenshot, ioc_list): ").strip()
    if not etype:
        print("  [warn] Evidence type cannot be empty.")
        return

    desc = input("  Description: ").strip()
    if not desc:
        print("  [warn] Description cannot be empty.")
        return

    src = input("  Source file path (blank for reference only): ").strip()
    source_path = src if src else None

    if add_evidence(current, stage, etype, desc, source_path=source_path):
        print(f"  Evidence attached to {stage}")


def _menu_list_evidence(current):
    """Option 10: list evidence, optionally filtered by stage."""
    print("  Stages:")
    for i, stage in enumerate(STAGES, start=1):
        print(f"    {i}. {stage}")
    raw = input("  Filter by stage (blank = all, 1-4 = specific): ").strip()

    stage_filter = None
    if raw:
        try:
            idx = int(raw) - 1
            if idx < 0 or idx >= len(STAGES):
                raise ValueError
            stage_filter = STAGES[idx]
        except ValueError:
            print("  [warn] Invalid stage number; showing all evidence.")
            stage_filter = None

    entries = list_evidence(current, stage=stage_filter)
    if not entries:
        print("  (no evidence)")
        return

    for e in entries:
        print(f"  [{e.get('timestamp', '?')}] [{e.get('stage', '?')}] "
              f"{e.get('type', '?')} — {e.get('description', '')}")
        if e.get('file'):
            print(f"      file: {e['file']}")


def _menu_close(current):
    """Option 11: close the current incident."""
    if current.get('status') == 'closed':
        print("  [warn] Incident is already closed.")
        return

    summary = input("  Closing summary: ").strip()
    if not summary:
        print("  [warn] Summary cannot be empty.")
        return

    sev_raw = input(
        "  Update severity? (blank to keep, else low/medium/high/critical): "
    ).strip().lower()
    new_sev = sev_raw if sev_raw else None

    if close_incident(current, summary, severity=new_sev):
        print(f"  Incident {current['id']} closed.")


def _menu_export(current):
    """Option 12: export current incident as Markdown."""
    path = input("  Output path (blank = default): ").strip()
    output_path = path if path else None

    if export_incident_markdown(current, output_path=output_path):
        where = output_path or f"{INCIDENTS_DIR}/{current['id']}.md"
        print(f"  Exported to {where}")

def ir_menu():
    """
    Interactive incident-response tracker menu.
    Returns when user chooses Exit, presses Ctrl+C, or sends EOF.
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

            print("  1.  List all incidents")
            print("  2.  Create new incident")
            print("  3.  Load an incident by ID")
            print("  4.  Add action to current incident")
            print("  5.  View current incident")
            print("  6.  Dashboard stats")
            print("  7.  Search incidents")
            print("  8.  Filter incidents")
            print("  9.  Add evidence to current incident")
            print("  10. List evidence of current incident")
            print("  11. Close current incident")
            print("  12. Export current incident as Markdown")
            print("  13. Exit")

            choice = input("Choice: ").strip()

            if choice == '1':
                _menu_list()

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
                    print("  [warn] Load or create an incident first.")
                    continue
                _menu_add_action(current)

            elif choice == '5':
                if current is None:
                    print("  [warn] No incident loaded.")
                    continue
                view_incident(current)

            elif choice == '6':
                _menu_dashboard()

            elif choice == '7':
                _menu_search()

            elif choice == '8':
                _menu_filter()

            elif choice == '9':
                if current is None:
                    print("  [warn] Load or create an incident first.")
                    continue
                _menu_add_evidence(current)

            elif choice == '10':
                if current is None:
                    print("  [warn] No incident loaded.")
                    continue
                _menu_list_evidence(current)

            elif choice == '11':
                if current is None:
                    print("  [warn] No incident loaded.")
                    continue
                _menu_close(current)

            elif choice == '12':
                if current is None:
                    print("  [warn] No incident loaded.")
                    continue
                _menu_export(current)

            elif choice == '13':
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
    Returns the incident dict, or None if incident creation fails.
    """
    if severity is None:
        severity = _auto_severity(findings)

    incident = create_incident(name, severity=severity, status='open')

    if incident is None:
        return None

    for key, summarizer in _SUMMARIZERS:
        items = findings.get(key) or []
        if not items:
            continue
        add_action(incident, 'Detection/Analysis', summarizer(items))

    return incident


def link_report_to_incident(incident, report_path):
    """
    Copy a report file into the incident's evidence directory and log
    a Preparation action. Returns True on success, False on failure.
    """
    if not validate_incident(incident):
        print("[warn] Cannot link report: invalid incident data.")
        return False

    if not os.path.exists(report_path):
        print(f"[warn] Report file not found: {report_path}")
        return False

    incident_id = incident['id']
    evidence_dir = os.path.join(INCIDENTS_DIR, f"{incident_id}_evidence")
    if not utils.ensure_dir(evidence_dir):
        return False

    timestamp_prefix = datetime.now().strftime('%Y%m%d-%H%M%S')
    dest_name = f"{timestamp_prefix}_{os.path.basename(report_path)}"
    dest_path = os.path.join(evidence_dir, dest_name)

    try:
        shutil.copy2(report_path, dest_path)
    except OSError as e:
        print(f"[warn] Failed to copy report: {e}")
        return False

    action = f"Attached evidence: {dest_name}"
    notes = f"Source: {report_path}"
    return add_action(incident, 'Preparation', action, notes=notes)

def export_incident_markdown(incident, output_path=None):
    """
    Render an incident as a Markdown file.
    Returns True on success, False on failure.
    """
    if not incident or not incident.get('id'):
        print("[warn] Cannot export: incident missing 'id'")
        return False

    incident_id = incident['id']
    name = incident.get('name', '(unnamed)')
    created = utils.fmt_ts(incident.get('created', ''))
    status = incident.get('status', 'open').upper()
    severity = incident.get('severity', 'low').upper()

    lines = []
    lines.append(f"# {incident_id} — {name}")
    lines.append('')
    lines.append(f"| Field | Value |")
    lines.append(f"| --- | --- |")
    lines.append(f"| ID | `{incident_id}` |")
    lines.append(f"| Created | {created} |")
    lines.append(f"| Status | **{status}** |")
    lines.append(f"| Severity | **{severity}** |")
    lines.append('')

    stages = incident.get('stages', {})
    total = 0

    for stage in STAGES:
        entries = stages.get(stage, [])
        total += len(entries)
        lines.append(f"## {stage}")
        lines.append('')
        if not entries:
            lines.append('_No actions logged._')
            lines.append('')
            continue

        for e in entries:
            ts = utils.fmt_ts(e.get('timestamp', ''))
            action = e.get('action', '(no action)')
            lines.append(f"- **{ts}** — {action}")
            notes = e.get('notes', '')
            if notes:
                lines.append(f"  - _{notes}_")
        lines.append('')

    lines.append('---')
    lines.append(f"_Total actions logged: {total}_")
    lines.append('')

    if output_path is None:
        output_path = os.path.join(INCIDENTS_DIR, f"{incident_id}.md")

    try:
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))
        return True
    except OSError as e:
        print(f"[warn] Failed to write markdown {output_path}: {e}")
        return False

def close_incident(incident, summary, severity=None):
    """
    Close an incident with a final Post-Incident summary action.
    Optionally update severity. Cannot close an already-closed incident.
    Returns True on success, False on failure.
    """
    if not validate_incident(incident):
        print("[warn] Cannot close: invalid incident data")
        return False

    if incident.get('status') == 'closed':
        print(f"[warn] Incident {incident['id']} is already closed")
        return False

    if not summary or not summary.strip():
        print("[warn] Cannot close: summary is required")
        return False

    original_status = incident.get('status', 'open')
    original_severity = incident.get('severity', 'low')

    if severity is not None:
        if severity not in SEVERITIES:
            print(f"[warn] Invalid severity {severity!r}; "
                  f"keeping {original_severity}")
        else:
            incident['severity'] = severity

    incident['status'] = 'closed'
    incident['closed_at'] = datetime.now().isoformat(timespec='seconds')

    ok = add_action(incident, 'Post-Incident', f"Incident closed: {summary.strip()}")

    if not ok:
        incident['status'] = original_status
        incident['severity'] = original_severity
        incident.pop('closed_at', None)
        return False

    return True

def search_incidents(query, case_sensitive=False):
    """
    Search incidents by substring across name, action text, and notes.
    Returns a list of match summaries (newest-first), each containing
    the incident's metadata plus a 'matches' list showing where the
    query hit.
    """
    if not isinstance(query, str) or not query.strip():
        print("[warn] Search query cannot be empty")
        return []

    needle = query if case_sensitive else query.lower()

    def contains(haystack):
        if not isinstance(haystack, str):
            return False
        if case_sensitive:
            return needle in haystack
        return needle in haystack.lower()

    results = []

    for summary in list_incidents():
        incident = load_incident(summary['id'])
        if incident is None:
            continue

        matches = []

        if contains(incident.get('name', '')):
            matches.append({
                'stage': '(name)',
                'timestamp': incident.get('created', ''),
                'snippet': incident.get('name', ''),
            })

        stages = incident.get('stages', {})
        for stage in STAGES:
            for entry in stages.get(stage, []):
                action = entry.get('action', '')
                notes = entry.get('notes', '')

                if contains(action):
                    matches.append({
                        'stage': stage,
                        'timestamp': entry.get('timestamp', ''),
                        'snippet': action,
                    })
                if contains(notes):
                    matches.append({
                        'stage': stage,
                        'timestamp': entry.get('timestamp', ''),
                        'snippet': notes,
                    })

        if matches:
            results.append({
                'id': incident['id'],
                'name': incident.get('name', '(unnamed)'),
                'created': incident.get('created', ''),
                'status': incident.get('status', 'open'),
                'severity': incident.get('severity', 'low'),
                'matches': matches,
            })

    results.sort(key=lambda r: r['created'], reverse=True)
    return results

def filter_incidents(status=None, severity=None, since=None, until=None):
    """
    Return incident summaries filtered by metadata.
    All provided filters are AND-ed. Newest-first.
    - status:   'open' or 'closed'
    - severity: 'low','medium','high','critical'
    - since:    ISO date/datetime string (inclusive)
    - until:    ISO date/datetime string (exclusive)
    Returns [] on invalid filter input.
    """
    if status is not None and status not in STATUSES:
        print(f"[warn] Invalid status filter: {status!r}")
        return []

    if severity is not None and severity not in SEVERITIES:
        print(f"[warn] Invalid severity filter: {severity!r}")
        return []

    since_dt = None
    until_dt = None

    if since is not None:
        try:
            since_dt = datetime.fromisoformat(since)
        except (ValueError, TypeError):
            print(f"[warn] Invalid 'since' value: {since!r}")
            return []

    if until is not None:
        try:
            until_dt = datetime.fromisoformat(until)
        except (ValueError, TypeError):
            print(f"[warn] Invalid 'until' value: {until!r}")
            return []

    results = []
    for summary in list_incidents():
        if status is not None and summary.get('status') != status:
            continue
        if severity is not None and summary.get('severity') != severity:
            continue

        if since_dt is not None or until_dt is not None:
            try:
                created_dt = datetime.fromisoformat(summary['created'])
            except (ValueError, TypeError, KeyError):
                continue

            if since_dt is not None and created_dt < since_dt:
                continue
            if until_dt is not None and created_dt >= until_dt:
                continue

        results.append(summary)

    return results

def dashboard_stats():
    """
    Return aggregate statistics across all incidents on disk.
    Used by the analyst/manager dashboard view.
    """
    summaries = list_incidents()

    total = len(summaries)
    by_status = {s: 0 for s in STATUSES}
    by_severity = {sev: 0 for sev in SEVERITIES}
    open_by_severity = {sev: 0 for sev in SEVERITIES}

    now = datetime.now()
    seven_days_ago = now - timedelta(days=7)

    open_ages = []
    new_last_7_days = 0
    closed_last_7_days = 0

    for s in summaries:
        status = s.get('status', 'open')
        severity = s.get('severity', 'low')

        if status in by_status:
            by_status[status] += 1
        if severity in by_severity:
            by_severity[severity] += 1
        if status == 'open' and severity in open_by_severity:
            open_by_severity[severity] += 1

        try:
            created = datetime.fromisoformat(s.get('created', ''))
        except (ValueError, TypeError):
            continue

        if created >= seven_days_ago:
            new_last_7_days += 1

        if status == 'open':
            age_days = (now - created).total_seconds() / 86400
            open_ages.append((age_days, s))
        elif status == 'closed':
            closed_at_str = s.get('closed_at')
            if closed_at_str:
                try:
                    closed_at = datetime.fromisoformat(closed_at_str)
                    if closed_at >= seven_days_ago:
                        closed_last_7_days += 1
                except (ValueError, TypeError):
                    pass

    oldest_open = None
    if open_ages:
        open_ages.sort(key=lambda x: x[0], reverse=True)
        age, s = open_ages[0]
        oldest_open = {
            'id': s['id'],
            'name': s['name'],
            'age_days': round(age, 2),
        }

    mean_open_age = (
        round(sum(a for a, _ in open_ages) / len(open_ages), 2)
        if open_ages else 0.0
    )

    return {
        'total': total,
        'by_status': by_status,
        'by_severity': by_severity,
        'open_by_severity': open_by_severity,
        'oldest_open': oldest_open,
        'mean_open_age_days': mean_open_age,
        'new_last_7_days': new_last_7_days,
        'closed_last_7_days': closed_last_7_days,
    }

def add_evidence(incident, stage, evidence_type, description, source_path=None):
    """
    Attach structured evidence to an incident.
    Optionally copies a file into the incident's evidence directory.
    Returns True on success, False on failure.
    """
    if not validate_incident(incident):
        print("[warn] Cannot add evidence: invalid incident data")
        return False

    if stage not in STAGES:
        print(f"[warn] Invalid stage: {stage!r}")
        return False

    if not isinstance(evidence_type, str) or not evidence_type.strip():
        print("[warn] Evidence type must be a non-empty string")
        return False

    if not isinstance(description, str) or not description.strip():
        print("[warn] Description must be a non-empty string")
        return False

    incident.setdefault('evidence', [])

    stored_filename = None

    if source_path is not None:
        if not os.path.exists(source_path):
            print(f"[warn] Evidence source not found: {source_path}")
            return False

        incident_id = incident['id']
        evidence_dir = os.path.join(
            INCIDENTS_DIR, f"{incident_id}_evidence"
        )
        if not utils.ensure_dir(evidence_dir):
            return False

        ts_prefix = datetime.now().strftime('%Y%m%d-%H%M%S')
        suffix = uuid.uuid4().hex[:8]
        stored_filename = (
            f"{ts_prefix}_{suffix}_{os.path.basename(source_path)}"
        )
        dest = os.path.join(evidence_dir, stored_filename)

        try:
            shutil.copy2(source_path, dest)
        except OSError as e:
            print(f"[warn] Failed to copy evidence: {e}")
            return False

    entry = {
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'stage': stage,
        'type': evidence_type.strip(),
        'description': description.strip(),
        'file': stored_filename,
    }

    incident['evidence'].append(entry)

    if not save_incident(incident):
        incident['evidence'].pop()
        return False

    return True

def list_evidence(incident, stage=None):
    """
    Return evidence attached to an incident, sorted chronologically.
    Optionally filter to a single lifecycle stage.
    """
    if not isinstance(incident, dict):
        return []

    entries = incident.get('evidence', [])
    if not isinstance(entries, list):
        return []

    if stage is not None:
        entries = [e for e in entries
                   if isinstance(e, dict) and e.get('stage') == stage]

    def sort_key(e):
        return e.get('timestamp', '') if isinstance(e, dict) else ''

    return sorted(entries, key=sort_key)

def export_all_incidents_markdown(directory):
    """
    Export every incident on disk to a .md file in `directory`.
    Returns True if at least one file was exported.
    """
    if not utils.ensure_dir(directory):
        return False

    summaries = list_incidents()
    if not summaries:
        print("[info] No incidents to export.")
        return False

    successes = 0
    failures = 0

    for s in summaries:
        incident = load_incident(s['id'])
        if incident is None:
            failures += 1
            continue

        output_path = os.path.join(directory, f"{incident['id']}.md")
        if export_incident_markdown(incident, output_path=output_path):
            successes += 1
        else:
            failures += 1

    total = len(summaries)
    print(f"[info] Exported {successes} of {total} incidents to {directory}"
          + (f" ({failures} failed)" if failures else ""))

    return successes > 0

if __name__ == '__main__':
    ir_menu()