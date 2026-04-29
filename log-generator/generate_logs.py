"""
Multi-Server Log Generator
============================
Generates realistic, diverse logs from multiple simulated servers.
Each server runs as a separate thread and produces logs with
weighted severity distributions (Low / Medium / High / Critical).

Logs are tagged with server ID and name using JSON format so that
Filebeat can forward structured metadata to Elasticsearch.
"""

import json
import os
import random
import time
import datetime
import threading
from server_config import SERVERS, MALICIOUS_IPS, NORMAL_IPS, USERS

LOG_DIR = "/logs"


def gen_timestamp():
    """Generate current ISO-format timestamp."""
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def pick_ip(template):
    """Choose malicious or normal IP based on log template context."""
    threat_keywords = ["attack", "failed", "inject", "brute", "unauthorized",
                       "exploit", "shell", "ddos", "breach", "stuffing",
                       "traversal", "xss", "csrf", "ssrf", "rce",
                       "escalation", "exfiltration", "smuggling", "bypass"]
    lower = template.lower()
    if any(kw in lower for kw in threat_keywords):
        return random.choice(MALICIOUS_IPS)
    return random.choice(NORMAL_IPS)


def fill_template(template):
    """Fill a log template with randomized realistic values."""
    ip = pick_ip(template)
    return template.format(
        user=random.choice(USERS),
        ip=ip,
        ms=random.randint(1, 800),
        num=random.randint(1000, 9999),
        attempt=random.randint(5, 100),
        cpu=random.randint(10, 99),
        mem=random.randint(2000, 7500),
        pct=random.randint(30, 95),
        read=random.randint(1, 200),
        write=random.randint(1, 150),
        port=random.choice([22, 80, 443, 3306, 5432, 8080, 8443]),
        rx=random.randint(100, 5000),
        tx=random.randint(50, 3000),
        pid=random.randint(1000, 65000),
        swap=random.randint(0, 2000),
        load1=round(random.uniform(0.1, 8.0), 2),
        load2=round(random.uniform(0.1, 6.0), 2),
        load3=round(random.uniform(0.1, 4.0), 2),
        node=random.randint(1, 5),
    )


def pick_severity(weights):
    """Select severity level using weighted random distribution."""
    levels = list(weights.keys())
    w = list(weights.values())
    return random.choices(levels, weights=w, k=1)[0]


SEVERITY_LABEL_MAP = {
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}


def write_log(server, severity, message):
    """
    Write a structured JSON log line to the server's log file.
    Format allows Filebeat to parse and forward metadata to Elasticsearch.
    """
    filepath = os.path.join(LOG_DIR, server["log_file"])
    log_entry = {
        "timestamp": gen_timestamp(),
        "server_id": server["server_id"],
        "server_name": server["name"],
        "environment": server["environment"],
        "severity": SEVERITY_LABEL_MAP[severity],
        "message": message,
    }
    line = json.dumps(log_entry) + "\n"
    with open(filepath, "a") as f:
        f.write(line)
    print(f"[{server['name']}] [{SEVERITY_LABEL_MAP[severity]}] {message[:120]}")


def server_loop(server):
    """
    Main loop for a single simulated server.
    Generates logs continuously with weighted severity distribution.
    """
    print(f"  → Server '{server['name']}' ({server['server_id']}) started — env: {server['environment']}")
    patterns = server["log_patterns"]
    weights = server["severity_weights"]

    # Initial burst of logs
    for _ in range(random.randint(5, 10)):
        severity = pick_severity(weights)
        template = random.choice(patterns[severity])
        write_log(server, severity, fill_template(template))

    # Continuous generation
    while True:
        # Generate 1-4 logs per cycle
        batch_size = random.randint(1, 4)
        for _ in range(batch_size):
            severity = pick_severity(weights)
            template = random.choice(patterns[severity])
            write_log(server, severity, fill_template(template))

        # Random sleep between 2-8 seconds to simulate realistic spacing
        time.sleep(random.uniform(2, 8))


def main():
    print("=" * 60)
    print("  Multi-Server Log Generator")
    print(f"  Simulating {len(SERVERS)} servers")
    print(f"  Output directory: {LOG_DIR}")
    print("=" * 60)

    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    # Start a thread for each simulated server
    threads = []
    for server in SERVERS:
        t = threading.Thread(target=server_loop, args=(server,), daemon=True)
        t.start()
        threads.append(t)

    # Keep main thread alive
    try:
        while True:
            time.sleep(60)
            print(f"[Generator] All {len(SERVERS)} servers active — {gen_timestamp()}")
    except KeyboardInterrupt:
        print("\nLog generator shutting down...")


if __name__ == "__main__":
    main()
