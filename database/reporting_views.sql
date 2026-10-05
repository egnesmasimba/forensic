-- SQLite. Apply explicitly to an administrator-controlled reporting copy.
-- Aggregation does not by itself guarantee anonymization of small populations.
CREATE VIEW IF NOT EXISTS forensic_case_workload AS
SELECT status, risk, COUNT(*) AS case_count, AVG(score) AS average_score,
       MIN(created_at) AS oldest_created_at
FROM cases GROUP BY status, risk;

CREATE VIEW IF NOT EXISTS forensic_alert_channels AS
SELECT channel, status, COUNT(*) AS alert_count, AVG(score) AS average_score,
       SUM(CASE WHEN case_id IS NULL THEN 1 ELSE 0 END) AS unassigned_case_count
FROM alerts GROUP BY channel, status;
