import random
import time
import datetime
import os

LOG_DIR = "/logs"

NORMAL_LOGS = [
    "INFO: User {user} logged in successfully from {ip}",
    "INFO: GET /api/v1/users - 200 OK ({ms}ms)",
    "INFO: POST /api/v1/orders - 201 Created ({ms}ms)",
    "INFO: Database query executed in {ms}ms",
    "INFO: Cache hit for key session:{user}",
    "INFO: Health check passed - all services operational",
    "INFO: Background job cleanup_expired_sessions completed",
    "INFO: File uploaded successfully by {user}: report_{num}.pdf",
    "INFO: Email notification sent to {user}@company.com",
    "DEBUG: Connection pool stats: active=5, idle=15, total=20",
    "INFO: Scheduled backup started for database main_db",
    "INFO: API rate limit check passed for {ip}",
    "INFO: User {user} updated profile settings",
    "INFO: Payment processed successfully - order #{num}",
    "INFO: Static assets served from CDN - 200 OK",
]

ATTACK_LOGS = [
    "ERROR: Multiple failed login attempts for user admin from {ip} - attempt {attempt}/10",
    "WARN: SQL injection attempt detected: ' OR 1=1 -- from {ip}",
    "CRITICAL: Brute force attack detected from {ip} - {attempt} attempts in 60s",
    "ERROR: Unauthorized access attempt to /admin/config from {ip}",
    "WARN: XSS payload detected in request body from {ip}: <script>alert('xss')</script>",
    "ERROR: Directory traversal attempt: GET /../../etc/passwd from {ip}",
    "CRITICAL: Suspicious file upload attempt: shell.php from {ip}",
    "WARN: Port scan detected from {ip} - scanning ports 22,80,443,3306,5432",
    "ERROR: Invalid JWT token - possible token forgery from {ip}",
    "CRITICAL: DDoS pattern detected - {attempt} requests/sec from {ip} subnet",
    "WARN: Command injection attempt in parameter: ; cat /etc/shadow from {ip}",
    "ERROR: Unauthorized API key usage detected from {ip}",
    "CRITICAL: Privilege escalation attempt by user guest from {ip}",
    "WARN: Suspicious user-agent: sqlmap/1.5 from {ip}",
    "ERROR: CSRF token mismatch - possible cross-site attack from {ip}",
]

SYSTEM_LOGS = [
    "syslog: CPU usage at {cpu}% on worker-node-{node}",
    "syslog: Memory usage: {mem}MB / 8192MB ({pct}%)",
    "syslog: Disk I/O: read={read}MB/s write={write}MB/s",
    "kernel: [UFW BLOCK] IN=eth0 SRC={ip} DST=10.0.0.1 PROTO=TCP DPT={port}",
    "syslog: Network interface eth0: RX={rx}MB TX={tx}MB",
    "systemd: Service nginx reloaded successfully",
    "sshd: Accepted publickey for deploy from {ip} port {port}",
    "sshd: Failed password for root from {ip} port {port} ssh2",
    "kernel: Out of memory: Killed process {pid} (java) total-vm:4096000kB",
    "cron: (root) CMD (/usr/bin/certbot renew --quiet)",
    "systemd: Started Docker Container {container}",
    "syslog: Swap usage: {swap}MB / 4096MB",
    "auditd: USER_AUTH pid={pid} uid=0 auid=1000 msg='op=PAM:authentication acct=\"root\" res=failed'",
    "syslog: Load average: {load1} {load2} {load3}",
    "kernel: TCP: request_sock_TCP: Possible SYN flooding on port {port}. Sending cookies.",
]

USERS = ["alice", "bob", "charlie", "david", "admin", "deploy", "guest"]
MALICIOUS_IPS = ["45.33.32.156", "185.220.101.35", "192.168.1.100", "10.10.14.5", "23.129.64.210"]
NORMAL_IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.50", "172.16.0.100", "192.168.0.5"]
CONTAINERS = ["web-app", "api-server", "db-postgres", "redis-cache", "nginx-proxy"]

def gen_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def fill_template(template):
    return template.format(
        user=random.choice(USERS),
        ip=random.choice(MALICIOUS_IPS if "attack" in template.lower() or "failed" in template.lower() or "inject" in template.lower() else NORMAL_IPS),
        ms=random.randint(1, 500),
        num=random.randint(1000, 9999),
        attempt=random.randint(5, 50),
        cpu=random.randint(10, 99),
        mem=random.randint(2000, 7500),
        pct=random.randint(30, 95),
        read=random.randint(1, 200),
        write=random.randint(1, 150),
        port=random.choice([22, 80, 443, 3306, 5432, 8080, 8443]),
        rx=random.randint(100, 5000),
        tx=random.randint(50, 3000),
        pid=random.randint(1000, 65000),
        container=random.choice(CONTAINERS),
        swap=random.randint(0, 2000),
        load1=round(random.uniform(0.1, 8.0), 2),
        load2=round(random.uniform(0.1, 6.0), 2),
        load3=round(random.uniform(0.1, 4.0), 2),
        node=random.randint(1, 5),
    )

def write_log(filename, message):
    filepath = os.path.join(LOG_DIR, filename)
    line = f"{gen_timestamp()} {message}\n"
    with open(filepath, "a") as f:
        f.write(line)
    print(f"[{filename}] {line.strip()}")

def main():
    print("=== Log Generator Started ===")
    print(f"Writing to: {LOG_DIR}")
    
    # Write initial burst
    for _ in range(10):
        write_log("app.log", fill_template(random.choice(NORMAL_LOGS)))
    for _ in range(3):
        write_log("system.log", fill_template(random.choice(SYSTEM_LOGS)))
    print("Initial logs written. Starting continuous generation...\n")

    cycle = 0
    while True:
        cycle += 1

        # Normal app logs (most frequent)
        for _ in range(random.randint(2, 5)):
            write_log("app.log", fill_template(random.choice(NORMAL_LOGS)))

        # System logs
        write_log("system.log", fill_template(random.choice(SYSTEM_LOGS)))

        # Attack logs every ~3 cycles (simulating periodic attacks)
        if cycle % 3 == 0:
            count = random.randint(1, 3)
            for _ in range(count):
                write_log("attack.log", fill_template(random.choice(ATTACK_LOGS)))
            print(f"  >> {count} ATTACK log(s) injected!")

        time.sleep(random.uniform(2, 5))

if __name__ == "__main__":
    main()
