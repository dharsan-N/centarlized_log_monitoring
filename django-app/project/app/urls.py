from django.urls import path
from . import views

urlpatterns = [
    path('servers/', views.get_servers, name='get_servers'),
    path('logs/', views.get_logs, name='get_logs'),
    path('threats/', views.get_threats, name='get_threats'),
    path('stats/', views.get_stats, name='get_stats'),
    path('detect/', views.run_detection, name='run_detection'),
    path('resolve/<int:threat_id>/', views.resolve_threat, name='resolve_threat'),
    path('blocked-ips/', views.get_blocked_ips, name='get_blocked_ips'),
    path('handled-logs/', views.get_handled_logs, name='get_handled_logs'),
]
