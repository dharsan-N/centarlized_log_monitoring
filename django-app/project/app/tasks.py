from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from django_apscheduler.jobstores import DjangoJobStore, register_events
from .services import process_and_store_logs
import logging

logger = logging.getLogger(__name__)

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_jobstore(DjangoJobStore(), "default")
    
    # Run every 1 minute
    scheduler.add_job(
        process_and_store_logs,
        trigger=IntervalTrigger(minutes=1),
        id="process_and_store_logs",
        max_instances=1,
        replace_existing=True,
    )
    
    register_events(scheduler)
    scheduler.start()
    print("Scheduler started. Monitoring logs...")
