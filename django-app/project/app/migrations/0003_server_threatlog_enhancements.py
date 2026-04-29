from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0002_threatlog_status'),
    ]

    operations = [
        # Create Server model
        migrations.CreateModel(
            name='Server',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('server_id', models.CharField(max_length=50, unique=True)),
                ('name', models.CharField(max_length=100)),
                ('environment', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True, default='')),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['server_id'],
            },
        ),
        # Add new fields to ThreatLog
        migrations.AddField(
            model_name='threatlog',
            name='server',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='threat_logs',
                to='app.server',
            ),
        ),
        migrations.AddField(
            model_name='threatlog',
            name='severity_level',
            field=models.CharField(
                choices=[('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High'), ('CRITICAL', 'Critical')],
                default='LOW',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='threatlog',
            name='source_ip',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='threatlog',
            name='attack_type',
            field=models.CharField(blank=True, default='', max_length=100),
        ),
        # Update ordering
        migrations.AlterModelOptions(
            name='threatlog',
            options={'ordering': ['-timestamp']},
        ),
    ]
