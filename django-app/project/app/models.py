from django.db import models

class ThreatLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    log_content = models.TextField()
    classification = models.CharField(max_length=50) # NORMAL or ATTACK
    risk_score = models.IntegerField(default=0)
    explanation = models.TextField()

    def __str__(self):
        return f"{self.classification} ({self.risk_score}) - {self.timestamp}"
