from django.urls import path
from . import views

urlpatterns = [
    path('servers/', views.get_servers, name='get_servers'),
    path('logs/', views.get_logs, name='get_logs'),
    path('threats/', views.get_threats, name='get_threats'),
    path('stats/', views.get_stats, name='get_stats'),
    path('analyze/', views.analyze_now, name='analyze_now'),
    path('resolve/<int:threat_id>/', views.resolve_threat, name='resolve_threat'),
]
