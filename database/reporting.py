"""Read aggregate SQL views from an administrator-controlled SQLite reporting copy.

Views are TEMP views on a read-only connection: source schema/data are never changed.
"""
from contextlib import closing
import argparse
import json
import re
import sqlite3
from pathlib import Path

VIEW_NAMES = ('forensic_case_workload', 'forensic_alert_channels')

_CREATE_VIEW = re.compile(r'\bCREATE\s+(TEMP\s+|TEMPORARY\s+)?VIEW\b', re.IGNORECASE)
_PLAIN_CREATE_VIEW = re.compile(r'\bCREATE\s+(?!TEMP\b|TEMPORARY\b)VIEW\b', re.IGNORECASE)


def temp_view_sql(sql):
    """Rewrite view definitions to TEMP views.

    The read-only connection is what actually protects the source database, but a
    silent miss here would turn a reporting read into a write attempt, so the
    rewrite is case-insensitive and verified instead of a plain substring swap.
    """
    rewritten, replaced = _CREATE_VIEW.subn(
        lambda match: 'CREATE TEMP VIEW' if not match.group(1)
        else 'CREATE ' + match.group(1).upper() + 'VIEW',
        sql,
    )
    if replaced == 0:
        raise ValueError('reporting_views.sql defines no views')
    if _PLAIN_CREATE_VIEW.search(rewritten):
        raise ValueError('reporting_views.sql still contains a non-temporary view definition')
    return rewritten


def summary(path):
    uri = Path(path).resolve().as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        sql = Path(__file__).with_name('reporting_views.sql').read_text(encoding='utf-8')
        connection.executescript(temp_view_sql(sql))
        # Confirm the views landed in the temp schema, so a reporting run can
        # never leave objects behind in the source database.
        temp = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_temp_master WHERE type='view'")}
        missing = [name for name in VIEW_NAMES if name not in temp]
        if missing:
            raise ValueError(f'reporting views were not created as TEMP views: {missing}')
        return {
            'cases': [dict(row) for row in connection.execute('SELECT * FROM forensic_case_workload ORDER BY status, risk')],
            'alerts': [dict(row) for row in connection.execute('SELECT * FROM forensic_alert_channels ORDER BY channel, status')],
        }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path)
    args = parser.parse_args()
    print(json.dumps(summary(args.database)))
