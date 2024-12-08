import re
import csv
from collections import defaultdict

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def count_requests_per_ip(logs):
    ip_counts = defaultdict(int)
    for log in logs:
        ip = log.split()[0]
        ip_counts[ip] += 1
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

def most_accessed_endpoint(logs):
    from collections import Counter

    endpoints = []

    for log in logs:
        try:
            parts = log.split('"')
            if len(parts) > 1:
                request_line = parts[1]  
                endpoint = request_line.split()[1]  
                endpoints.append(endpoint)

        except IndexError:
            continue

    endpoint_counts = Counter(endpoints)

    if not endpoint_counts:  
        return None, []  

    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
    return most_accessed, endpoint_counts

def detect_suspicious_activity(logs, threshold=10):
    failed_logins = defaultdict(int)
    for log in logs:
        if '401' in log or 'Invalid credentials' in log:
            ip = log.split()[0]
            failed_logins[ip] += 1
    flagged_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    return flagged_ips

def save_to_csv(requests, most_accessed, suspicious, output_file='log_analysis_results.csv'):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(requests)
        
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(most_accessed)
        
        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        writer.writerows(suspicious.items())

def main():
    log_file = 'sample.log'  # Replace with the path to your log file
    logs = parse_log_file(log_file)
    
    ip_requests = count_requests_per_ip(logs)
    print("Requests per IP Address:")
    for ip, count in ip_requests:
        print(f"{ip: <20} {count}")
    
    most_accessed, all_endpoints = most_accessed_endpoint(logs)
    if most_accessed:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    else:
        print("\nNo valid endpoints found.")
    
    suspicious_activity = detect_suspicious_activity(logs)
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip: <20} {count}")
    
    save_to_csv(ip_requests, most_accessed or ('None', 0), suspicious_activity)
    print("\nResults saved to 'log_analysis_results.csv'")

    

if __name__ == "__main__":
    main()
