"""
Services Module
================
Handles Elasticsearch queries, Ollama AI analysis, email alerting,
and server-aware log processing pipeline.
"""

import json
import re
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

import requests
from elasticsearch import Elasticsearch
from django.conf import settings

from .models import ThreatLog, Server

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Attack type detection patterns
# ---------------------------------------------------------------------------
ATTACK_PATTERNS = {
    "SSH Brute Force": [r"brute force.*ssh", r"failed password.*ssh", r"dictionary attack"],
    "SQL Injection": [r"sql injection", r"OR '?1'?='?1", r"UNION SELECT", r"information_schema"],
    "XSS Attack": [r"xss", r"<script>", r"document\.cookie"],
    "DDoS Attack": [r"ddos", r"req/s from", r"syn flooding"],
    "Directory Traversal": [r"directory traversal", r"\.\./\.\./", r"etc/passwd"],
    "Brute Force Login": [r"brute force", r"multiple failed login", r"credential stuffing"],
    "Web Shell": [r"web shell", r"shell\.php", r"cmd\.php"],
    "Command Injection": [r"command injection", r"; cat /etc", r"reverse shell"],
    "Privilege Escalation": [r"privilege escalation", r"rootkit", r"CVE-\d{4}"],
    "CSRF Attack": [r"csrf", r"cross-site"],
    "SSRF Attack": [r"ssrf", r"server-side request forgery"],
    "RCE Attack": [r"remote code execution", r"log4shell", r"rce"],
    "Token Forgery": [r"token forgery", r"invalid jwt", r"compromised key"],
    "Data Exfiltration": [r"exfiltration", r"COPY TO STDOUT"],
    "Port Scan": [r"port scan", r"scanning ports"],
    "Unauthorized Access": [r"unauthorized access", r"unauthorized.*endpoint", r"authentication bypass"],
}


def detect_attack_type(log_message):
    """Detect the type of attack from a log message using pattern matching."""
    lower_msg = log_message.lower()
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, lower_msg, re.IGNORECASE):
                return attack_type
    return ""


def extract_ip(log_message):
    """Extract the first IP address found in a log message."""
    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_message)
    return match.group(0) if match else None


def map_severity_to_risk(severity):
    """Map severity level to a risk score range."""
    ranges = {
        "LOW": (0, 25),
        "MEDIUM": (26, 50),
        "HIGH": (51, 80),
        "CRITICAL": (81, 100),
    }
    low, high = ranges.get(severity.upper(), (0, 25))
    import random
    return random.randint(low, high)


# ---------------------------------------------------------------------------
# Elasticsearch Service
# ---------------------------------------------------------------------------
class ElasticsearchService:
    """Handles all Elasticsearch interactions."""

    def __init__(self):
        self.es = Elasticsearch([settings.ELASTICSEARCH_HOST])

    def fetch_recent_logs(self, minutes=5, index="filebeat-*", **filters):
        """
        Fetch recent logs from ES with optional filtering.
        
        Filters:
            server_id (str): Filter by server_id field
            severity (str): Filter by severity field
            keyword (str): Full-text search on message field
            source_ip (str): Filter by IP in message
            date_from (str): ISO date start
            date_to (str): ISO date end
        """
        try:
            must_clauses = []
            
            # Time range
            time_range = {"range": {"@timestamp": {}}}
            if filters.get("date_from"):
                time_range["range"]["@timestamp"]["gte"] = filters["date_from"]
            else:
                time_range["range"]["@timestamp"]["gte"] = f"now-{minutes}m"
            if filters.get("date_to"):
                time_range["range"]["@timestamp"]["lte"] = filters["date_to"]
            else:
                time_range["range"]["@timestamp"]["lte"] = "now"
            must_clauses.append(time_range)

            # Server filter
            if filters.get("server_id"):
                must_clauses.append({"term": {"server_id": filters["server_id"]}})

            # Severity filter
            if filters.get("severity"):
                must_clauses.append({"term": {"severity": filters["severity"].upper()}})

            # Keyword search
            if filters.get("keyword"):
                must_clauses.append({"match_phrase": {"message": filters["keyword"]}})

            # IP search in message
            if filters.get("source_ip"):
                must_clauses.append({"match_phrase": {"message": filters["source_ip"]}})

            query = {
                "query": {"bool": {"must": must_clauses}},
                "size": 200,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }

            res = self.es.search(index=index, body=query, ignore_unavailable=True)
            hits = res.get("hits", {}).get("hits", [])
            logs = []
            for hit in hits:
                source = hit["_source"]
                logs.append({
                    "message": source.get("message", ""),
                    "server_id": source.get("server_id", "unknown"),
                    "server_name": source.get("server_name", "unknown"),
                    "environment": source.get("environment", ""),
                    "severity": source.get("severity", "LOW"),
                    "timestamp": source.get("timestamp", source.get("@timestamp", "")),
                })
            return logs
        except Exception as e:
            logger.error(f"Error fetching logs from ES: {e}")
            return []

    def get_server_stats(self, index="filebeat-*"):
        """Get aggregated statistics per server."""
        try:
            query = {
                "size": 0,
                "query": {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
                "aggs": {
                    "by_server": {
                        "terms": {"field": "server_id", "size": 50},
                        "aggs": {
                            "by_severity": {
                                "terms": {"field": "severity", "size": 10}
                            },
                            "server_name": {
                                "terms": {"field": "server_name", "size": 1}
                            },
                        },
                    },
                    "by_severity": {
                        "terms": {"field": "severity", "size": 10}
                    },
                    "top_ips": {
                        "terms": {"field": "message", "size": 0}  # placeholder
                    },
                },
            }
            res = self.es.search(index=index, body=query, ignore_unavailable=True)
            return res.get("aggregations", {})
        except Exception as e:
            logger.error(f"Error fetching stats from ES: {e}")
            return {}

    def get_top_attacking_ips(self, index="filebeat-*"):
        """Extract top attacking IPs from high/critical severity logs."""
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
                            {"terms": {"severity": ["HIGH", "CRITICAL"]}},
                        ]
                    }
                },
                "size": 500,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }
            res = self.es.search(index=index, body=query, ignore_unavailable=True)
            hits = res.get("hits", {}).get("hits", [])

            ip_counts = {}
            for hit in hits:
                msg = hit["_source"].get("message", "")
                ip = extract_ip(msg)
                if ip and not ip.startswith(("192.168.", "10.0.", "172.16.")):
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
            return [{"ip": ip, "count": count} for ip, count in sorted_ips[:10]]
        except Exception as e:
            logger.error(f"Error fetching top IPs: {e}")
            return []


# ---------------------------------------------------------------------------
# Active Response Service
# ---------------------------------------------------------------------------
import os

class ActiveResponseService:
    """Handles automatic IP blocking and storage of patched logs."""

    def __init__(self):
        self.blocked_ips_file = os.path.join(settings.BASE_DIR, 'blocked_ips.json')
        self.patched_logs_file = os.path.join(settings.BASE_DIR, 'patched_logs.json')
        
        # Ensure files exist
        if not os.path.exists(self.blocked_ips_file):
            with open(self.blocked_ips_file, 'w') as f: json.dump([], f)
        if not os.path.exists(self.patched_logs_file):
            with open(self.patched_logs_file, 'w') as f: json.dump([], f)

    def get_blocked_ips(self):
        try:
            with open(self.blocked_ips_file, 'r') as f: return json.load(f)
        except Exception: return []

    def block_ip(self, ip, severity, attack_type, server_name):
        blocked = self.get_blocked_ips()
        if any(b['ip'] == ip for b in blocked):
            return False
        
        blocked.append({
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "attack_type": attack_type,
            "server_name": server_name
        })
        with open(self.blocked_ips_file, 'w') as f:
            json.dump(blocked, f, indent=2)
        return True

    def get_patched_logs(self):
        try:
            with open(self.patched_logs_file, 'r') as f: return json.load(f)
        except Exception: return []

    def store_patched_log(self, original_log, detected_issue, action_taken):
        patched = self.get_patched_logs()
        patched.append({
            "original_log": original_log,
            "detected_issue": detected_issue,
            "action_taken": action_taken,
            "timestamp": datetime.now().isoformat()
        })
        # Keep last 1000 to avoid huge file
        if len(patched) > 1000: patched = patched[-1000:]
        with open(self.patched_logs_file, 'w') as f:
            json.dump(patched, f, indent=2)


# ---------------------------------------------------------------------------
# Email Alert Service
# ---------------------------------------------------------------------------
class AlertService:
    """Sends email alerts for High and Critical severity events."""

    def __init__(self):
        self.smtp_host = getattr(settings, "SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(getattr(settings, "SMTP_PORT", 587))
        self.email_from = getattr(settings, "ALERT_EMAIL_FROM", "")
        self.email_to = getattr(settings, "ALERT_EMAIL_TO", "")
        self.smtp_user = getattr(settings, "SMTP_USERNAME", "")
        self.smtp_pass = getattr(settings, "SMTP_PASSWORD", "")
        self.enabled = bool(self.email_from and self.email_to and self.smtp_user)

    def should_alert(self, severity_level):
        """Only alert on HIGH and CRITICAL severity."""
        return self.enabled and severity_level in ("HIGH", "CRITICAL")

    def send_alert(self, threat_log):
        """Send a formatted email alert for a detected threat."""
        if not self.enabled:
            logger.info("Email alerting is not configured — skipping alert.")
            return False

        try:
            server_name = threat_log.server.name if threat_log.server else "Unknown Server"
            server_id = threat_log.server.server_id if threat_log.server else "N/A"

            subject = f"🚨 [{threat_log.severity_level}] Security Alert — {server_name}"

            html_body = f"""
            <html>
            <body style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #0a0e1a; color: #e2e8f0; padding: 24px;">
                <div style="max-width: 600px; margin: 0 auto; background: #1a2235; border-radius: 16px; border: 1px solid #2a3450; overflow: hidden;">
                    <div style="background: linear-gradient(135deg, #6366f1, #8b5cf6); padding: 24px; text-align: center;">
                        <h1 style="margin: 0; color: white; font-size: 22px;">⚠️ Security Alert</h1>
                        <p style="margin: 8px 0 0; color: rgba(255,255,255,0.8); font-size: 14px;">Log Monitoring System</p>
                    </div>
                    <div style="padding: 24px;">
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 12px 0; color: #64748b; font-size: 13px; border-bottom: 1px solid #2a3450;">Severity</td>
                                <td style="padding: 12px 0; font-weight: 700; color: {'#ef4444' if threat_log.severity_level == 'CRITICAL' else '#f59e0b'}; font-size: 15px; border-bottom: 1px solid #2a3450;">{threat_log.severity_level}</td>
                            </tr>
                            <tr>
                                <td style="padding: 12px 0; color: #64748b; font-size: 13px; border-bottom: 1px solid #2a3450;">Server</td>
                                <td style="padding: 12px 0; color: #e2e8f0; font-size: 14px; border-bottom: 1px solid #2a3450;">{server_name} ({server_id})</td>
                            </tr>
                            <tr>
                                <td style="padding: 12px 0; color: #64748b; font-size: 13px; border-bottom: 1px solid #2a3450;">Timestamp</td>
                                <td style="padding: 12px 0; color: #e2e8f0; font-size: 14px; border-bottom: 1px solid #2a3450;">{threat_log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
                            </tr>
                            <tr>
                                <td style="padding: 12px 0; color: #64748b; font-size: 13px; border-bottom: 1px solid #2a3450;">Source IP</td>
                                <td style="padding: 12px 0; color: #e2e8f0; font-size: 14px; border-bottom: 1px solid #2a3450;">{threat_log.source_ip or 'N/A'}</td>
                            </tr>
                            <tr>
                                <td style="padding: 12px 0; color: #64748b; font-size: 13px; border-bottom: 1px solid #2a3450;">Attack Type</td>
                                <td style="padding: 12px 0; color: #e2e8f0; font-size: 14px; border-bottom: 1px solid #2a3450;">{threat_log.attack_type or 'General Threat'}</td>
                            </tr>
                            <tr>
                                <td style="padding: 12px 0; color: #64748b; font-size: 13px; border-bottom: 1px solid #2a3450;">Risk Score</td>
                                <td style="padding: 12px 0; color: #e2e8f0; font-size: 14px; border-bottom: 1px solid #2a3450;">{threat_log.risk_score}/100</td>
                            </tr>
                            <tr>
                                <td style="padding: 12px 0; color: #64748b; font-size: 13px; border-bottom: 1px solid #2a3450;">Classification</td>
                                <td style="padding: 12px 0; color: #ef4444; font-weight: 600; font-size: 14px; border-bottom: 1px solid #2a3450;">{threat_log.classification}</td>
                            </tr>
                        </table>
                        <div style="margin-top: 20px; padding: 16px; background: rgba(0,0,0,0.3); border-radius: 8px; border: 1px solid #2a3450;">
                            <p style="color: #64748b; font-size: 12px; margin: 0 0 8px; text-transform: uppercase; letter-spacing: 1px;">Log Content</p>
                            <p style="color: #94a3b8; font-size: 12px; font-family: 'Courier New', monospace; line-height: 1.6; margin: 0; white-space: pre-wrap;">{threat_log.log_content[:500]}</p>
                        </div>
                    </div>
                    <div style="padding: 16px 24px; border-top: 1px solid #2a3450; text-align: center;">
                        <p style="color: #64748b; font-size: 11px; margin: 0;">Log Monitoring &amp; Security Analytics Platform</p>
                    </div>
                </div>
            </body>
            </html>
            """

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.email_from
            msg["To"] = self.email_to
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as smtp:
                smtp.starttls()
                smtp.login(self.smtp_user, self.smtp_pass)
                smtp.sendmail(self.email_from, self.email_to.split(","), msg.as_string())

            logger.info(f"Alert email sent for threat {threat_log.id} to {self.email_to}")
            return True

        except Exception as e:
            logger.error(f"Failed to send alert email: {e}")
            return False


# ---------------------------------------------------------------------------
# Log Processing Pipeline
# ---------------------------------------------------------------------------
def sync_servers():
    """Register servers from Elasticsearch data into the Django database."""
    es_service = ElasticsearchService()
    try:
        query = {
            "size": 0,
            "aggs": {
                "servers": {
                    "terms": {"field": "server_id", "size": 50},
                    "aggs": {
                        "server_name": {"terms": {"field": "server_name", "size": 1}},
                        "environment": {"terms": {"field": "environment", "size": 1}},
                    },
                }
            },
        }
        res = es_service.es.search(index="filebeat-*", body=query, ignore_unavailable=True)
        buckets = res.get("aggregations", {}).get("servers", {}).get("buckets", [])

        for bucket in buckets:
            sid = bucket["key"]
            name_buckets = bucket.get("server_name", {}).get("buckets", [])
            env_buckets = bucket.get("environment", {}).get("buckets", [])
            name = name_buckets[0]["key"] if name_buckets else sid
            env = env_buckets[0]["key"] if env_buckets else "Unknown"

            Server.objects.update_or_create(
                server_id=sid,
                defaults={"name": name, "environment": env, "is_active": True},
            )
        logger.info(f"Synced {len(buckets)} servers from Elasticsearch.")
    except Exception as e:
        logger.error(f"Error syncing servers: {e}")


def process_and_store_logs():
    """
    Main processing pipeline:
    1. Fetch recent logs from Elasticsearch
    2. Detect attacks using rules
    3. Block IPs for High/Critical threats and store to JSON
    4. Store results with enriched metadata
    5. Send email alerts for High/Critical events
    """
    es_service = ElasticsearchService()
    logs = es_service.fetch_recent_logs(minutes=1)

    if not logs:
        return

    sync_servers()
    alert_service = AlertService()
    response_service = ActiveResponseService()

    # Track processed messages in memory for this run to avoid dupes in this batch
    processed_msgs = set()

    for log in logs:
        msg = log.get("message", "")
        if not msg or msg in processed_msgs:
            continue
            
        # Check DB to prevent duplicate processing of the same exact log string
        if ThreatLog.objects.filter(log_content=msg).exists():
            continue
            
        processed_msgs.add(msg)
        
        severity = log.get("severity", "LOW")
        attack_type = detect_attack_type(msg)
        source_ip = extract_ip(msg)
        server_id = log.get("server_id", "unknown")
        server_name = log.get("server_name", "unknown")
        
        server_obj = None
        try:
            server_obj = Server.objects.get(server_id=server_id)
        except Server.DoesNotExist:
            pass
            
        classification = "ATTACK" if severity in ["HIGH", "CRITICAL"] or attack_type else "NORMAL"
        risk_score = map_severity_to_risk(severity)
        explanation = f"Detected {attack_type} pattern" if attack_type else "Normal system behavior"
        
        threat = ThreatLog.objects.create(
            log_content=msg,
            classification=classification,
            risk_score=risk_score,
            explanation=explanation,
            server=server_obj,
            severity_level=severity,
            source_ip=source_ip,
            attack_type=attack_type,
        )
        
        if classification == "ATTACK" and severity in ["HIGH", "CRITICAL"]:
            action_taken = "No IP found to block"
            if source_ip:
                is_blocked = response_service.block_ip(source_ip, severity, attack_type or "Unknown", server_name)
                if is_blocked:
                    action_taken = f"Blocked IP {source_ip}"
                else:
                    action_taken = f"IP {source_ip} already blocked"
            
            response_service.store_patched_log(msg, attack_type or "Unknown", action_taken)
            
            if alert_service.should_alert(severity):
                alert_service.send_alert(threat)
