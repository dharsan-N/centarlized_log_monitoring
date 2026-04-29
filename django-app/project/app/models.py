from django.db import models


class Server(models.Model):
    """Represents a simulated or real server being monitored."""
    server_id = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=100)
    environment = models.CharField(max_length=100)
    description = models.TextField(blank=True, default='')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.server_id})"

    class Meta:
        ordering = ['server_id']


class ThreatLog(models.Model):
    """Stores AI-analyzed log entries with threat classification."""
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('RESOLVED', 'Resolved'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    log_content = models.TextField()
    classification = models.CharField(max_length=50)  # NORMAL or ATTACK
    risk_score = models.IntegerField(default=0)
    explanation = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    server = models.ForeignKey(Server, on_delete=models.SET_NULL, null=True, blank=True, related_name='threat_logs')
    severity_level = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='LOW')
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    attack_type = models.CharField(max_length=100, blank=True, default='')

    def __str__(self):
        return f"{self.classification} ({self.risk_score}) - {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']
