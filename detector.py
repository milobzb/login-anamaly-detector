from datetime import datetime, date
import csv

trusted_ips = []

with open('trusted_ips.txt', 'r') as file:
    for line in file:
        trusted_ips.append(line.strip())

user_logins = {}

with open('logins.csv', 'r') as file:
    reader = csv.DictReader(file)
    for row in reader:
        username = row['username']

        if username in user_logins:
            user_logins[username].append(row)
        else:
            user_logins[username] = [row]

flagged = []

for username, logins in user_logins.items():
    logins.sort(key=lambda x: x['login_time'])

    for i in range(len(logins) - 1):
        current = logins[i]
        next_login = logins[i + 1]

        if current['ip_address'] in trusted_ips or next_login['ip_address'] in trusted_ips:
            continue

        if current['city'] != next_login['city']:
            time1 = datetime.strptime(current['login_time'], '%Y-%m-%d %H:%M')
            time2 = datetime.strptime(next_login['login_time'], '%Y-%m-%d %H:%M')
            gap_minutes = (time2 - time1).total_seconds() / 60

            if gap_minutes < 120:
                flagged.append({
                    'username': username,
                    'from_city': current['city'],
                    'to_city': next_login['city'],
                    'gap_minutes': int(gap_minutes),
                    'from_ip': current['ip_address'],
                    'to_ip': next_login['ip_address']
                })

clean_users = len(user_logins) - len(set(f['username'] for f in flagged))

with open('report.txt', 'w') as output:
    output.write("LOGIN ANOMALY DETECTOR REPORT\n")
    output.write("Generated: " + str(date.today()) + "\n")
    output.write("\nFLAGGED ANOMALIES:\n\n")

    for result in flagged:
        output.write(result['username'] + " | " + result['from_city'] + " -> " + result['to_city'] + " | " + str(result['gap_minutes']) + " mins apart\n")
        output.write("From IP: " + result['from_ip'] + " | To IP: " + result['to_ip'] + "\n\n")

    output.write("SUMMARY:\n")
    output.write("Total users scanned: " + str(len(user_logins)) + "\n")
    output.write("Anomalies detected: " + str(len(flagged)) + "\n")
    output.write("Clean users: " + str(clean_users) + "\n")

print("Report generated successfully. Open report.txt to view results.")