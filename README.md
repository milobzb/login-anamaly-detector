# Login Anomaly Detector

A Python automation tool that detects impossible travel anomalies in authentication logs by analyzing consecutive login events per user. Built as a portfolio project to demonstrate threat detection and IAM security automation skills.

## The Problem

In enterprise environments, compromised credentials are one of the most common attack vectors. A reliable sign of account compromise is impossible travel: a user logging in from New York and then London 45 minutes later is physically impossible. Manually reviewing thousands of authentication log entries across hundreds of users every day is not scalable. Security teams need automation to surface these anomalies instantly.

## What It Does

- Reads a CSV authentication log containing login events with timestamps, cities, and IP addresses
- Groups login events by user and sorts them chronologically
- Compares consecutive login pairs per user
- Skips login pairs where either IP belongs to a trusted corporate VPN whitelist
- Flags any pair where the city changed within an impossibly short time window (default: 120 minutes)
- Generates a timestamped audit report summarizing all detected anomalies

## Technologies Used

- Python 3
- csv module (built-in)
- datetime module (built-in)

## How To Run It

1. Clone this repository
2. Make sure Python 3 is installed on your machine
3. Navigate to the project folder in your terminal
4. Run the script:

```bash
python detector.py
```

5. Open report.txt to view the generated anomaly report

## Configuration

The impossible travel time threshold is set inside detector.py:

```python
if gap_minutes < 120:
```

Adjust this value to match your organization's detection policy.

Corporate VPN IP addresses are managed in trusted_ips.txt, one IP per line:
192.168.1.20
10.0.0.15
192.168.2.11

Any login originating from a trusted IP is automatically skipped during anomaly detection, eliminating false positives from legitimate VPN usage.

## Example Output
LOGIN ANOMALY DETECTOR REPORT
Generated: 2026-07-09
FLAGGED ANOMALIES:
user1 | New York -> London | 45 mins apart
From IP: 192.168.1.10 | To IP: 203.0.113.22
user4 | Miami -> Tokyo | 30 mins apart
From IP: 172.16.0.5 | To IP: 198.51.100.9
SUMMARY:
Total users scanned: 5
Anomalies detected: 2
Clean users: 3

## How It Works

The detector uses three core techniques:

- A dictionary groups each user's login events together for isolated analysis
- A sort by login_time ensures events are always compared chronologically regardless of log order
- A consecutive pair loop compares each login against the one immediately after it, checking for city changes within the time threshold

## Real World Context

This tool mirrors the impossible travel detection logic used by enterprise SIEM platforms like Microsoft Sentinel, Splunk, and IBM QRadar. Those platforms ingest authentication logs at scale and apply behavioral rules to surface anomalies for SOC analysts to investigate. This project demonstrates that same detection pattern in a lightweight, portable Python script.

Designed for enterprise and federal contractor environments where corporate VPN IP ranges are known and controlled. The trusted IP whitelist eliminates false positives from legitimate VPN usage, a common challenge in real world impossible travel detection.

## Author

Emanuel Botros  
DevOps & Identity Operations Engineer | CompTIA Security+  
UCF MS Cybersecurity & Privacy (Expected May 2027)
