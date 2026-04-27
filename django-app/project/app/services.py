import json
import logging
from elasticsearch import Elasticsearch
from django.conf import settings
import requests
from .models import ThreatLog
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ElasticsearchService:
    def __init__(self):
        self.es = Elasticsearch([settings.ELASTICSEARCH_HOST])

    def fetch_recent_logs(self, minutes=5, index="filebeat-*"):
        try:
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{minutes}m",
                            "lte": "now"
                        }
                    }
                },
                "size": 100,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            res = self.es.search(index=index, body=query, ignore_unavailable=True)
            hits = res.get('hits', {}).get('hits', [])
            logs = [hit['_source'].get('message', '') for hit in hits if 'message' in hit['_source']]
            return logs
        except Exception as e:
            logger.error(f"Error fetching logs from ES: {e}")
            return []

class OllamaService:
    def __init__(self):
        self.host = settings.OLLAMA_HOST
        self.model = "llama3"

    def analyze_logs(self, logs):
        if not logs:
            return None
        
        prompt = (
            "Analyze the following log entries and classify the overall activity as either NORMAL or ATTACK. "
            "Assign a risk score from 0 to 100. Provide a brief explanation. "
            "Respond ONLY in the following JSON format without markdown wrapping:\n"
            "{\"classification\": \"NORMAL/ATTACK\", \"risk_score\": 0-100, \"explanation\": \"reasoning here\"}\n\n"
            "Logs:\n" + "\n".join(logs)
        )

        try:
            response = requests.post(f"{self.host}/api/generate", json={
                "model": self.model,
                "prompt": prompt,
                "stream": False
            }, timeout=300)
            
            if response.status_code == 200:
                result = response.json().get('response', '{}')
                try:
                    # Sometimes LLM wraps json in ```json ... ```
                    if "```json" in result:
                        result = result.split("```json")[1].split("```")[0].strip()
                    elif "```" in result:
                        result = result.split("```")[1].strip()
                    
                    data = json.loads(result)
                    return data
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse JSON from Ollama: {result}")
                    return None
            else:
                logger.error(f"Ollama API returned status code {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error communicating with Ollama: {e}")
            return None

def process_and_store_logs():
    es_service = ElasticsearchService()
    logs = es_service.fetch_recent_logs(minutes=1)
    
    if not logs:
        print("No new logs found.")
        return

    print(f"Fetched {len(logs)} logs. Analyzing the 20 most recent logs...")
    ollama_service = OllamaService()
    analysis = ollama_service.analyze_logs(logs[:20])

    if analysis:
        print(f"Analysis result: {analysis}")
        log_content_summary = "\\n".join(logs[:5]) + ("..." if len(logs) > 5 else "")
        ThreatLog.objects.create(
            log_content=log_content_summary,
            classification=analysis.get('classification', 'UNKNOWN'),
            risk_score=analysis.get('risk_score', 0),
            explanation=analysis.get('explanation', '')
        )
        if analysis.get('classification') == 'ATTACK':
            print("ALERT: ATTACK DETECTED!")
    else:
        print("Log analysis failed.")
