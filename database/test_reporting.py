from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from reporting import summary, temp_view_sql


class TempViewSqlTests(unittest.TestCase):
    def test_rewrites_plain_views(self):
        rewritten = temp_view_sql('CREATE VIEW a AS SELECT 1;')
        self.assertEqual(rewritten, 'CREATE TEMP VIEW a AS SELECT 1;')

    def test_rewrite_ignores_case_and_spacing(self):
        # A plain substring swap would miss these and leave a real CREATE VIEW.
        for sql in ('create view a as select 1;', 'CREATE  VIEW a AS SELECT 1;',
                    'CrEaTe\tVIEW a AS SELECT 1;'):
            with self.subTest(sql=sql):
                self.assertIn('CREATE TEMP VIEW', temp_view_sql(sql).upper().replace('\t', ' '))

    def test_rewrite_is_idempotent(self):
        once = temp_view_sql('CREATE VIEW a AS SELECT 1;')
        self.assertEqual(temp_view_sql(once), once)
        self.assertEqual(temp_view_sql(temp_view_sql('CREATE TEMP VIEW a AS SELECT 1;')),
                         'CREATE TEMP VIEW a AS SELECT 1;')

    def test_rejects_sql_without_views(self):
        with self.assertRaises(ValueError):
            temp_view_sql('SELECT 1;')


class ReportingTests(unittest.TestCase):
    def test_aggregates_without_changing_source(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'report.sqlite'
            with closing(sqlite3.connect(path)) as db:
                db.executescript("CREATE TABLE cases(status,risk,score,created_at); CREATE TABLE alerts(channel,status,score,case_id); INSERT INTO cases VALUES('new','high',80,'2026-01-01'),('new','high',60,'2026-02-01'); INSERT INTO alerts VALUES('network','open',50,NULL);")
            before = path.read_bytes()
            result = summary(path)
            self.assertEqual(result['cases'][0]['case_count'], 2)
            self.assertEqual(result['cases'][0]['average_score'], 70)
            self.assertEqual(result['alerts'][0]['unassigned_case_count'], 1)
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaises(sqlite3.OperationalError):
                summary(Path(root) / 'missing.sqlite')


if __name__ == '__main__':
    unittest.main()
