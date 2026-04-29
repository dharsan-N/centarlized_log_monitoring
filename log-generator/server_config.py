"""
Server Configuration Module
============================
Defines simulated server profiles for the log monitoring system.
Each server has a unique identity, environment type, and specific
log patterns with weighted severity distributions.

To add a new server, simply append a new dict to SERVERS list.
"""

SERVERS = [
    {
        "server_id": "srv-001",
        "name": "linux-gateway",
        "environment": "Linux System",
        "description": "Primary Linux gateway server handling network traffic and system operations",
        "log_file": "server_srv-001.log",
        "log_patterns": {
            "low": [
                "INFO: System boot completed successfully on linux-gateway",
                "INFO: Cron job /usr/bin/logrotate executed successfully",
                "INFO: User {user} logged in via SSH from {ip}",
                "INFO: Package update check completed - all packages up to date",
                "INFO: Disk usage on /dev/sda1: {pct}% utilized",
                "INFO: NTP time sync successful with pool.ntp.org",
                "DEBUG: Systemd service nginx status: active (running)",
                "INFO: Firewall rule added: ALLOW {ip} on port {port}",
                "INFO: Backup cron job completed - /var/backups/daily.tar.gz",
                "INFO: Load average: {load1} {load2} {load3} - within normal range",
            ],
            "medium": [
                "WARN: Disk usage on /dev/sda1 at {pct}% - approaching threshold",
                "WARN: High memory utilization: {mem}MB / 8192MB ({pct}%)",
                "WARN: Unusual outbound traffic detected to {ip}:{port} - {rx}MB transferred",
                "WARN: Failed su attempt for root by user {user} from tty1",
                "WARN: Kernel: TCP connection table near capacity - {attempt} active connections",
                "WARN: auditd: Suspicious file permission change on /etc/shadow by uid=1001",
            ],
            "high": [
                "ERROR: sshd: Multiple failed password attempts for root from {ip} - {attempt} failures",
                "ERROR: kernel: [UFW BLOCK] Repeated SRC={ip} DST=10.0.0.1 PROTO=TCP DPT=22",
                "ERROR: auditd: Unauthorized binary execution /tmp/.hidden/payload by uid=1001",
                "ERROR: PAM: Authentication failure for admin from {ip} - account may be targeted",
                "ERROR: Suspicious cron entry added: * * * * * curl http://{ip}/beacon",
            ],
            "critical": [
                "CRITICAL: sshd: Brute force attack detected from {ip} - {attempt} attempts in 30s",
                "CRITICAL: kernel: Possible rootkit detected - hidden process with PID {pid}",
                "CRITICAL: auditd: Privilege escalation exploit attempted - CVE-2024-1086 from {ip}",
                "CRITICAL: Reverse shell connection established from {ip}:{port} to internal host",
            ],
        },
        "severity_weights": {"low": 50, "medium": 25, "high": 15, "critical": 10},
    },
    {
        "server_id": "srv-002",
        "name": "web-server-nginx",
        "environment": "Web Server",
        "description": "Nginx web server handling HTTP/HTTPS traffic and serving the application frontend",
        "log_file": "server_srv-002.log",
        "log_patterns": {
            "low": [
                "INFO: GET /index.html - 200 OK ({ms}ms) from {ip}",
                "INFO: GET /api/v1/health - 200 OK ({ms}ms)",
                "INFO: POST /api/v1/login - 200 OK ({ms}ms) from {ip}",
                "INFO: Static asset served: /assets/main.css - 304 Not Modified",
                "INFO: SSL certificate valid - expires in 45 days",
                "INFO: Upstream connection to backend:8080 established ({ms}ms)",
                "INFO: GET /api/v1/users - 200 OK ({ms}ms) user={user}",
                "INFO: Access log rotated successfully - new file: access.log.{num}",
                "DEBUG: Connection pool: active=12 idle=38 max=50",
                "INFO: Rate limiter: {ip} - 15/100 requests used in current window",
            ],
            "medium": [
                "WARN: GET /admin/login - 403 Forbidden from {ip} - user-agent: python-requests/2.28",
                "WARN: Rate limit threshold approached: {ip} - 85/100 requests",
                "WARN: Slow response detected: GET /api/v1/reports - {ms}ms (threshold: 500ms)",
                "WARN: Malformed HTTP request from {ip} - invalid header detected",
                "WARN: TLS handshake failure with {ip} - unsupported cipher suite",
                "WARN: Suspicious bot activity detected from {ip} - user-agent: Scrapy/2.8",
            ],
            "high": [
                "ERROR: XSS payload detected in POST /api/v1/comments from {ip}: <script>document.cookie</script>",
                "ERROR: SQL injection attempt: GET /api/v1/users?id=1' OR '1'='1 from {ip}",
                "ERROR: Directory traversal: GET /../../etc/passwd from {ip} - blocked",
                "ERROR: CSRF token mismatch on POST /api/v1/transfer from {ip}",
                "ERROR: Unauthorized file upload attempt: POST /upload/shell.php from {ip}",
            ],
            "critical": [
                "CRITICAL: DDoS attack detected - {attempt} req/s from {ip} subnet - triggering mitigation",
                "CRITICAL: Web shell detected at /uploads/cmd.php - immediate response required",
                "CRITICAL: Server-Side Request Forgery (SSRF) to internal metadata endpoint from {ip}",
                "CRITICAL: Remote Code Execution attempt via Log4Shell payload from {ip}",
            ],
        },
        "severity_weights": {"low": 55, "medium": 22, "high": 15, "critical": 8},
    },
    {
        "server_id": "srv-003",
        "name": "ssh-bastion",
        "environment": "SSH Service",
        "description": "SSH bastion host acting as secure entry point for administrative access",
        "log_file": "server_srv-003.log",
        "log_patterns": {
            "low": [
                "INFO: sshd: Accepted publickey for {user} from {ip} port {port} ssh2",
                "INFO: sshd: Session opened for user {user} by uid=0",
                "INFO: sshd: Session closed for user {user}",
                "INFO: sshd: Key regeneration completed successfully",
                "INFO: sshd: Server listening on 0.0.0.0 port 22",
                "INFO: PAM: Session opened for user {user} by (uid=0)",
                "INFO: sshd: Connection from {ip} port {port} - authorized key matched",
                "DEBUG: sshd: SSH2_MSG_KEXINIT received from {ip}",
            ],
            "medium": [
                "WARN: sshd: Failed password for {user} from {ip} port {port} ssh2",
                "WARN: sshd: Invalid user admin from {ip} port {port}",
                "WARN: sshd: Connection from {ip} dropped - too many authentication failures",
                "WARN: sshd: Received disconnect from {ip}: Bye Bye [preauth]",
                "WARN: sshd: Unusual key exchange algorithm requested from {ip}",
            ],
            "high": [
                "ERROR: sshd: Failed password for root from {ip} port {port} - {attempt} consecutive failures",
                "ERROR: sshd: PAM {attempt} more authentication failures; user=root from {ip}",
                "ERROR: sshd: Refused connect from {ip} - host is in deny list",
                "ERROR: sshd: Possible break-in attempt from {ip} - reverse mapping check failed",
            ],
            "critical": [
                "CRITICAL: sshd: Brute force SSH attack from {ip} - {attempt} failed attempts in 60 seconds",
                "CRITICAL: sshd: Compromised key detected for user {user} from {ip} - unauthorized access",
                "CRITICAL: sshd: Dictionary attack in progress from {ip} - cycling through usernames",
                "CRITICAL: sshd: Successful root login from unknown IP {ip} - potential breach",
            ],
        },
        "severity_weights": {"low": 45, "medium": 28, "high": 17, "critical": 10},
    },
    {
        "server_id": "srv-004",
        "name": "database-postgres",
        "environment": "Database Server",
        "description": "PostgreSQL database server managing application data and user records",
        "log_file": "server_srv-004.log",
        "log_patterns": {
            "low": [
                "INFO: PostgreSQL: Connection authorized: user={user} database=app_db from {ip}",
                "INFO: PostgreSQL: Checkpoint complete - wrote 128 buffers ({ms}ms)",
                "INFO: PostgreSQL: Autovacuum completed on table public.users",
                "INFO: PostgreSQL: Query executed in {ms}ms - SELECT on users table",
                "INFO: PostgreSQL: Backup pg_dump completed successfully",
                "INFO: PostgreSQL: Replication lag: 0.2s - within acceptable range",
                "DEBUG: PostgreSQL: Shared buffer hit ratio: 98.5%",
                "INFO: PostgreSQL: Connection from {ip}:{port} - SSL enabled",
            ],
            "medium": [
                "WARN: PostgreSQL: Slow query detected ({ms}ms): SELECT * FROM logs WHERE ... (full scan)",
                "WARN: PostgreSQL: Connection limit approaching - {attempt}/100 active connections",
                "WARN: PostgreSQL: Temporary file created for sort operation - {mem}MB",
                "WARN: PostgreSQL: Authentication failed for user {user} from {ip}",
                "WARN: PostgreSQL: Deadlock detected between transactions {pid} and {num}",
            ],
            "high": [
                "ERROR: PostgreSQL: Multiple auth failures for user admin from {ip} - {attempt} attempts",
                "ERROR: PostgreSQL: Suspicious query: DROP TABLE users from {ip} - blocked by policy",
                "ERROR: PostgreSQL: Unauthorized schema modification attempt from {ip}",
                "ERROR: PostgreSQL: Data exfiltration pattern detected - large COPY TO STDOUT from {ip}",
            ],
            "critical": [
                "CRITICAL: PostgreSQL: SQL injection via application - UNION SELECT from information_schema from {ip}",
                "CRITICAL: PostgreSQL: Unauthorized superuser access from {ip} - privilege escalation",
                "CRITICAL: PostgreSQL: Mass DELETE operation on production table users from {ip}",
            ],
        },
        "severity_weights": {"low": 55, "medium": 25, "high": 13, "critical": 7},
    },
    {
        "server_id": "srv-005",
        "name": "api-gateway",
        "environment": "API Gateway",
        "description": "API gateway managing microservice routing, authentication, and rate limiting",
        "log_file": "server_srv-005.log",
        "log_patterns": {
            "low": [
                "INFO: API Gateway: Request routed to user-service - 200 OK ({ms}ms)",
                "INFO: API Gateway: JWT token validated for user {user} from {ip}",
                "INFO: API Gateway: Health check on order-service: healthy ({ms}ms)",
                "INFO: API Gateway: Rate limit reset for {ip} - new window started",
                "INFO: API Gateway: Request logged: GET /api/v2/products from {ip}",
                "INFO: API Gateway: Circuit breaker for payment-service: CLOSED (healthy)",
                "DEBUG: API Gateway: Request tracing ID: req-{num} - latency {ms}ms",
                "INFO: API Gateway: CORS preflight handled for {ip}",
            ],
            "medium": [
                "WARN: API Gateway: Rate limit exceeded for {ip} - 429 Too Many Requests",
                "WARN: API Gateway: Expired JWT token from {ip} - user={user}",
                "WARN: API Gateway: Circuit breaker for payment-service: HALF-OPEN - monitoring",
                "WARN: API Gateway: Unusual API call pattern from {ip} - {attempt} requests to /api/v2/admin",
                "WARN: API Gateway: Request size exceeds limit from {ip} - 15MB payload blocked",
            ],
            "high": [
                "ERROR: API Gateway: Invalid JWT signature detected from {ip} - possible token forgery",
                "ERROR: API Gateway: API key abuse detected - key k_{num} used from {attempt} different IPs",
                "ERROR: API Gateway: Unauthorized access to internal admin endpoint from {ip}",
                "ERROR: API Gateway: Request smuggling attempt detected from {ip}",
            ],
            "critical": [
                "CRITICAL: API Gateway: Mass credential stuffing attack - {attempt} login attempts from {ip} subnet",
                "CRITICAL: API Gateway: Authentication bypass detected on /api/v2/admin from {ip}",
                "CRITICAL: API Gateway: Circuit breaker OPEN for ALL downstream services - system degraded",
            ],
        },
        "severity_weights": {"low": 50, "medium": 27, "high": 15, "critical": 8},
    },
]

# IPs used in log generation
MALICIOUS_IPS = [
    "45.33.32.156", "185.220.101.35", "23.129.64.210",
    "91.240.118.172", "103.235.46.39", "198.51.100.23",
    "203.0.113.42", "31.13.195.17", "77.247.181.163",
    "62.102.148.68",
]

NORMAL_IPS = [
    "192.168.1.10", "192.168.1.20", "10.0.0.50",
    "172.16.0.100", "192.168.0.5", "10.0.1.15",
    "172.16.1.200", "192.168.2.30",
]

USERS = ["alice", "bob", "charlie", "david", "admin", "deploy", "guest", "jenkins", "monitor", "devops"]
