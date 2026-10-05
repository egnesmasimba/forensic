SELECT status, COUNT(*) AS case_count
FROM cases
GROUP BY status
ORDER BY status
