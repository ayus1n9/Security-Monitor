import json
import os
from datetime import datetime

def fmt_ts(iso_str):
    """
    Convert an ISO-8601 timestamp string to 'YYYY-MM-DD HH:MM:SS'.
    Returns '' for None/empty input, and the raw string on parse failure.
    """
    if not iso_str:
        return ''
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return str(iso_str)

def ensure_dir(path):
    """
    Ensure a directory exists. Returns True on success, False on failure.
    Idempotent: safe to call when the directory already exists.
    """
    if not path:
        print("[warn] ensure_dir called with empty path")
        return False

    try:
        os.makedirs(path, exist_ok=True)
        return True
    except OSError as e:
        print(f"[warn] Failed to create directory {path}: {e}")
        return False

def load_json(filepath):
    """
    Load JSON from a file. Returns the parsed object, or None on failure.
    Prints a warning on missing/corrupt files.
    """
    if not os.path.exists(filepath):
        print(f"[warn] File not found: {filepath}")
        return None

    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[warn] Corrupt JSON in {filepath}: {e}")
        return None
    except OSError as e:
        print(f"[warn] Failed to read {filepath}: {e}")
        return None


def save_json(filepath, data):
    """
    Write a JSON-serializable object to a file (pretty-printed).
    Ensures parent directory exists. Returns True on success, False on failure.
    """
    parent = os.path.dirname(filepath)
    if parent and not ensure_dir(parent):
        return False

    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except (OSError, TypeError) as e:
        print(f"[warn] Failed to write {filepath}: {e}")
        return False

if __name__ == '__main__':
    cases = [
        '2026-09-22T16:20:42',
        '2026-09-22 16:20:42',
        '2026-09-22T16:20:42+00:00',
        '',
        None,
        'not-a-date',
        123,
    ]
    for c in cases:
        print(f'{c!r:45} -> {fmt_ts(c)!r}')

    print()
    print('--- ensure_dir smoke test ---')
    print(ensure_dir('data/test_dir_1/nested/deep'))
    print(ensure_dir('data/test_dir_1/nested/deep'))
    print(ensure_dir(''))
    print(ensure_dir(None))
    print(ensure_dir('utils.py'))
    print()
    print('--- load_json / save_json smoke test ---')
    test_data = {'name': 'Test', 'count': 3, 'tags': ['a', 'b']}
    print('save:', save_json('data/test_io.json', test_data))
    print('load:', load_json('data/test_io.json'))
    print('missing:', load_json('data/nope.json'))
    with open('data/bad.json', 'w') as f:
        f.write('{not valid json')
        
    print('corrupt:', load_json('data/bad.json'))
    print('bad data:', save_json('data/test_bad.json', {'bad': {1, 2, 3}}))