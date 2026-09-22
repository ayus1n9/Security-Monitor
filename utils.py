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