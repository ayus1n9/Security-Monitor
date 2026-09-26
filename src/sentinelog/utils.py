import json
import os
import tempfile
from datetime import datetime

DEFAULT_CONFIG = {
    'brute_force_threshold': 5,
    'brute_force_window_minutes': 5,
    'allowed_ports': [22, 80, 443, 53, 123],
    'blocklist_path': 'data/blocklist.txt',
    'log_path': 'data/sample.log',
    'incidents_dir': 'data/incidents',
    'report_output': 'data/report.txt',
}

def fmt_ts(iso_str):
    """
    Convert an ISO-8601 timestamp string to
    'YYYY-MM-DD HH:MM:SS'.

    Returns an empty string for None/empty input,
    and the original value as a string when parsing fails.
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
    Ensure a directory exists.

    Returns True on success and False on failure.
    Safe to call when the directory already exists.
    """
    if not path:
        print("[warn] ensure_dir called with empty path")
        return False

    try:
        os.makedirs(path, exist_ok=True)
        return True

    except OSError as e:
        print(
            f"[warn] Failed to create directory {path}: {e}"
        )
        return False


def load_json(filepath):
    """
    Load JSON from a file.

    Returns the parsed object, or None when the file cannot
    be read or contains invalid JSON.
    """
    if not isinstance(filepath, str) or not filepath:
        print("[warn] Invalid JSON file path.")
        return None

    if not os.path.isfile(filepath):
        print(f"[warn] File not found: {filepath}")
        return None

    try:
        with open(
            filepath,
            'r',
            encoding='utf-8'
        ) as file:
            return json.load(file)

    except json.JSONDecodeError as e:
        print(
            f"[warn] Corrupt JSON in {filepath}: {e}"
        )
        return None

    except (OSError, UnicodeError) as e:
        print(
            f"[warn] Failed to read {filepath}: {e}"
        )
        return None


def save_json(filepath, data):
    """
    Atomically write a JSON-serializable object to a file.

    The parent directory is created automatically.

    Returns True on success and False on failure.

    A temporary file is written first and then atomically
    replaces the target file. This reduces the chance of
    leaving a partially written JSON file if the process
    is interrupted during the write.
    """
    if not isinstance(filepath, str) or not filepath:
        print("[warn] Invalid JSON file path.")
        return False

    parent = os.path.dirname(filepath)

    if parent and not ensure_dir(parent):
        return False

    temp_path = None

    try:
        # Use the target directory so os.replace() stays
        # on the same filesystem.
        temp_dir = parent if parent else '.'

        fd, temp_path = tempfile.mkstemp(
            prefix='.tmp-',
            suffix='.json',
            dir=temp_dir,
            text=True
        )

        with os.fdopen(
            fd,
            'w',
            encoding='utf-8'
        ) as file:
            json.dump(
                data,
                file,
                indent=2,
                ensure_ascii=False
            )
            file.write('\n')
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, filepath)
        temp_path = None

        return True

    except (OSError, TypeError, ValueError) as e:
        print(
            f"[warn] Failed to write {filepath}: {e}"
        )
        return False

    finally:
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def _validate_config(config):
    """
    Validate configuration values.

    Returns True when the configuration has valid types
    and values, otherwise False.
    """
    if not isinstance(config, dict):
        return False

    threshold = config.get('brute_force_threshold')
    window = config.get('brute_force_window_minutes')
    allowed_ports = config.get('allowed_ports')

    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold <= 0
    ):
        return False

    if (
        not isinstance(window, int)
        or isinstance(window, bool)
        or window <= 0
    ):
        return False

    if not isinstance(allowed_ports, list):
        return False

    for port in allowed_ports:
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 0 <= port <= 65535
        ):
            return False

    for key in (
        'blocklist_path',
        'log_path',
        'incidents_dir',
        'report_output',
    ):
        if not isinstance(config.get(key), str):
            return False

        if not config[key]:
            return False

    return True


def load_config(path='config.json'):
    """
    Load config.json and merge it over DEFAULT_CONFIG.

    If the configuration file is missing, corrupt, or contains
    invalid configuration values, the default configuration
    is returned.

    Unknown configuration keys are ignored.
    """
    loaded = load_json(path)

    if loaded is None:
        return dict(DEFAULT_CONFIG)

    if not isinstance(loaded, dict):
        print("[warn] Configuration must contain a JSON object.")
        return dict(DEFAULT_CONFIG)

    # Only allow known configuration keys.
    merged = dict(DEFAULT_CONFIG)

    for key in DEFAULT_CONFIG:
        if key in loaded:
            merged[key] = loaded[key]

    if not _validate_config(merged):
        print(
            "[warn] Invalid configuration values; "
            "using defaults."
        )
        return dict(DEFAULT_CONFIG)

    return merged