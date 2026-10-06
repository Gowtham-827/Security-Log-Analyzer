# Security Log Analyzer
Parses SSH `auth.log` entries and raises alerts. Standard library only.

```bash
python log_analyzer.py sample_auth.log --year 2026
python log_analyzer.py /var/log/auth.log --threshold 5 --window 10 --csv alerts.csv
python log_analyzer.py sample_auth.log --year 2026 --json
```
Detections: **brute_force** (N failures in a sliding window), **user_enumeration** (many usernames from one IP),
**success_after_failures** (possible compromise, CRITICAL). Exit code `1` when alerts exist (usable in cron/CI).
