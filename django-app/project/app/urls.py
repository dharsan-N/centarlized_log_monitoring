from django.urls import path
from . import views

urlpatterns = [
    path('logs/', views.get_logs, name='get_logs'),
    path('threats/', views.get_threats, name='get_threats'),
    path('analyze/', views.analyze_now, name='analyze_now'),
    path('resolve/<int:threat_id>/', views.resolve_threat, name='resolve_threat'),
]
