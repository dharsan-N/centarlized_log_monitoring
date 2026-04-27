from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import ThreatLog
from .services import ElasticsearchService, process_and_store_logs

def dashboard(request):
    """Render the main dashboard UI"""
    return render(request, 'dashboard.html')


@api_view(['GET'])
def get_logs(request):
    """Fetch raw logs from Elasticsearch"""
    es_service = ElasticsearchService()
    logs = es_service.fetch_recent_logs(minutes=60)
    return Response({"status": "success", "count": len(logs), "logs": logs})

@api_view(['GET'])
def get_threats(request):
    """Fetch detected threats from the database"""
    threats = ThreatLog.objects.all().order_by('-timestamp')[:50]
    data = [
        {
            "id": t.id,
            "timestamp": t.timestamp,
            "classification": t.classification,
            "risk_score": t.risk_score,
            "explanation": t.explanation,
            "log_content": t.log_content,
            "status": t.status
        } for t in threats
    ]
    return Response({"status": "success", "count": len(data), "threats": data})

@csrf_exempt
@api_view(['POST'])
def analyze_now(request):
    """Trigger a manual analysis of recent logs"""
    process_and_store_logs()
    return Response({"status": "success", "message": "Manual analysis triggered and completed (if logs were present)."})

@csrf_exempt
@api_view(['POST'])
def resolve_threat(request, threat_id):
    """Mark a specific threat as resolved"""
    try:
        threat = ThreatLog.objects.get(id=threat_id)
        threat.status = 'RESOLVED'
        threat.save()
        return Response({"status": "success", "message": f"Threat {threat_id} marked as RESOLVED."})
    except ThreatLog.DoesNotExist:
        return Response({"status": "error", "message": "Threat not found."}, status=404)

