from django.apps import AppConfig
import sys

class AppConfigClass(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app'

    def ready(self):
        # Prevent scheduler from running multiple times (e.g., in runserver auto-reload or migrations)
        if 'runserver' in sys.argv or 'gunicorn' in sys.argv:
            import os
            # Django runserver runs two processes by default, we only want to start the scheduler in the main one
            if os.environ.get('RUN_MAIN', None) != 'true' and 'runserver' in sys.argv:
                return
            from . import tasks
            tasks.start_scheduler()
