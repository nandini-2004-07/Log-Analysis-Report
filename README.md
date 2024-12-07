# Log-Analysis-Report
import re
from collections import defaultdict
import csv

# Threshold for suspicious activity detection
FAILED_LOGIN_THRESHOLD = 10

def analyze_log(content):
    ip_request_count = defaultdict(int)
    endpoint_access_count = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    for line in content.strip().split("\n"):
        match = re.search(r'(\d+\.\d+\.\d+\.\d+).*"(\w+) (.*?) HTTP.*" (\d+)', line)
        if match:
            ip = match.group(1)
            endpoint = match.group(3)
            status_code = match.group(4)

            # Count requests by IP
            ip_request_count[ip] += 1

            # Count endpoint accesses
            endpoint_access_count[endpoint] += 1

            # Detect failed login attempts
            if status_code == "401":
                failed_login_attempts[ip] += 1

    return ip_request_count, endpoint_access_count, failed_login_attempts

def save_to_csv(ip_requests, endpoints, failed_logins):
    with open("log_analysis_results.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        if endpoints:
            most_accessed = max(endpoints.items(), key=lambda x: x[1])
            writer.writerow([most_accessed[0], most_accessed[1]])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in sorted(failed_logins.items(), key=lambda x: x[1], reverse=True):
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

def display_results(ip_requests, endpoints, failed_logins):
    print("\nRequests per IP:")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}: {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if endpoints:
        most_accessed = max(endpoints.items(), key=lambda x: x[1])
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in sorted(failed_logins.items(), key=lambda x: x[1], reverse=True):
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip}: {count} failed login attempts")

if __name__ == "__main__":
    # Sample log content
    LOG_CONTENT = """
    192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
    ...
    """

    ip_requests, endpoints, failed_logins = analyze_log(LOG_CONTENT)
    display_results(ip_requests, endpoints, failed_logins)
    save_to_csv(ip_requests, endpoints, failed_logins)
