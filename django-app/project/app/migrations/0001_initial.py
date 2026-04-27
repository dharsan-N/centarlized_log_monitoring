from django.db import migrations, models

class Migration(migrations.Migration):

    initial = True
    dependencies = []

    operations = [
        migrations.CreateModel(
            name='ThreatLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('log_content', models.TextField()),
                ('classification', models.CharField(max_length=50)),
                ('risk_score', models.IntegerField(default=0)),
                ('explanation', models.TextField()),
            ],
        ),
    ]
