"""
Views Module
=============
REST API endpoints and dashboard rendering for the
log monitoring and security analytics platform.
"""

from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.db.models import Count, Avg, Q

from .models import ThreatLog, Server
from .services import ElasticsearchService, process_and_store_logs, ActiveResponseService


def dashboard(request):
    """Render the main dashboard UI."""
    return render(request, "dashboard.html")


@api_view(["GET"])
def get_servers(request):
    """Fetch all registered servers with their threat statistics."""
    servers = Server.objects.all()
    data = []
    for s in servers:
        threat_stats = ThreatLog.objects.filter(server=s).aggregate(
            total=Count("id"),
            attacks=Count("id", filter=Q(classification="ATTACK")),
            avg_risk=Avg("risk_score"),
        )
        data.append({
            "id": s.id,
            "server_id": s.server_id,
            "name": s.name,
            "environment": s.environment,
            "description": s.description,
            "is_active": s.is_active,
            "total_threats": threat_stats["total"],
            "attack_count": threat_stats["attacks"],
            "avg_risk": round(threat_stats["avg_risk"] or 0, 1),
        })
    return Response({"status": "success", "count": len(data), "servers": data})


@api_view(["GET"])
def get_logs(request):
    """
    Fetch logs from Elasticsearch with optional filters.
    
    Query params:
        server_id - filter by server
        severity - LOW/MEDIUM/HIGH/CRITICAL
        keyword - text search in message
        source_ip - IP address filter
        date_from - ISO date start
        date_to - ISO date end
        minutes - time range in minutes (default: 60)
    """
    es_service = ElasticsearchService()

    filters = {}
    if request.GET.get("server_id"):
        filters["server_id"] = request.GET["server_id"]
    if request.GET.get("severity"):
        filters["severity"] = request.GET["severity"]
    if request.GET.get("keyword"):
        filters["keyword"] = request.GET["keyword"]
    if request.GET.get("source_ip"):
        filters["source_ip"] = request.GET["source_ip"]
    if request.GET.get("date_from"):
        filters["date_from"] = request.GET["date_from"]
    if request.GET.get("date_to"):
        filters["date_to"] = request.GET["date_to"]

    minutes = int(request.GET.get("minutes", 60))
    logs = es_service.fetch_recent_logs(minutes=minutes, **filters)
    return Response({"status": "success", "count": len(logs), "logs": logs})


@api_view(["GET"])
def get_threats(request):
    """
    Fetch detected threats with optional filters.
    
    Query params:
        server_id - filter by server
        severity - LOW/MEDIUM/HIGH/CRITICAL
        classification - NORMAL/ATTACK
        status - PENDING/RESOLVED
        limit - max results (default: 50)
    """
    queryset = ThreatLog.objects.select_related("server").all()

    if request.GET.get("server_id"):
        queryset = queryset.filter(server__server_id=request.GET["server_id"])
    if request.GET.get("severity"):
        queryset = queryset.filter(severity_level=request.GET["severity"].upper())
    if request.GET.get("classification"):
        queryset = queryset.filter(classification=request.GET["classification"].upper())
    if request.GET.get("status"):
        queryset = queryset.filter(status=request.GET["status"].upper())

    limit = int(request.GET.get("limit", 50))
    threats = queryset[:limit]

    data = [
        {
            "id": t.id,
            "timestamp": t.timestamp,
            "classification": t.classification,
            "risk_score": t.risk_score,
            "explanation": t.explanation,
            "log_content": t.log_content,
            "status": t.status,
            "severity_level": t.severity_level,
            "source_ip": t.source_ip,
            "attack_type": t.attack_type,
            "server_id": t.server.server_id if t.server else None,
            "server_name": t.server.name if t.server else "Unknown",
        }
        for t in threats
    ]
    return Response({"status": "success", "count": len(data), "threats": data})


@api_view(["GET"])
def get_stats(request):
    """
    Get aggregated dashboard statistics.
    Returns server-wise counts, severity distribution,
    top attacking IPs, and overall metrics.
    """
    es_service = ElasticsearchService()

    # DB-based stats
    total_threats = ThreatLog.objects.count()
    pending_attacks = ThreatLog.objects.filter(classification="ATTACK", status="PENDING").count()
    normal_count = ThreatLog.objects.filter(classification="NORMAL").count()
    avg_risk = ThreatLog.objects.aggregate(avg=Avg("risk_score"))["avg"] or 0

    # Severity distribution from DB
    severity_dist = list(
        ThreatLog.objects.values("severity_level")
        .annotate(count=Count("id"))
        .order_by("severity_level")
    )

    # Server-wise stats
    server_stats = list(
        ThreatLog.objects.filter(server__isnull=False)
        .values("server__server_id", "server__name")
        .annotate(
            total=Count("id"),
            attacks=Count("id", filter=Q(classification="ATTACK")),
            avg_risk=Avg("risk_score"),
        )
        .order_by("server__server_id")
    )

    # Top attacking IPs from ES
    top_ips = es_service.get_top_attacking_ips()

    return Response({
        "status": "success",
        "stats": {
            "total_threats": total_threats,
            "pending_attacks": pending_attacks,
            "normal_count": normal_count,
            "avg_risk": round(avg_risk, 1),
            "severity_distribution": severity_dist,
            "server_stats": server_stats,
            "top_attacking_ips": top_ips,
        },
    })


@csrf_exempt
@api_view(["POST"])
def run_detection(request):
    """Trigger a manual log processing and detection pipeline."""
    process_and_store_logs()
    return Response({
        "status": "success",
        "message": "Detection pipeline completed. Threats processed and responded to.",
    })


@csrf_exempt
@api_view(["POST"])
def resolve_threat(request, threat_id):
    """Mark a specific threat as resolved."""
    try:
        threat = ThreatLog.objects.get(id=threat_id)
        threat.status = "RESOLVED"
        threat.save()
        return Response({"status": "success", "message": f"Threat {threat_id} marked as RESOLVED."})
    except ThreatLog.DoesNotExist:
        return Response({"status": "error", "message": "Threat not found."}, status=404)

@api_view(["GET"])
def get_blocked_ips(request):
    """Fetch all automatically blocked IPs."""
    service = ActiveResponseService()
    ips = service.get_blocked_ips()
    # Apply optional filters
    if request.GET.get("server_id"):
        ips = [ip for ip in ips if ip.get("server_name") == request.GET["server_id"]]
    if request.GET.get("severity"):
        ips = [ip for ip in ips if ip.get("severity") == request.GET["severity"]]
    if request.GET.get("attack_type"):
        ips = [ip for ip in ips if request.GET["attack_type"].lower() in ip.get("attack_type", "").lower()]
        
    return Response({"status": "success", "count": len(ips), "blocked_ips": ips[::-1]})

@api_view(["GET"])
def get_handled_logs(request):
    """Fetch logs that were processed and patched."""
    service = ActiveResponseService()
    logs = service.get_patched_logs()
    return Response({"status": "success", "count": len(logs), "handled_logs": logs[::-1]})
