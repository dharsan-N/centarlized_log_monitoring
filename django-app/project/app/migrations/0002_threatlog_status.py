from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='threatlog',
            name='status',
            field=models.CharField(default='PENDING', max_length=20),
        ),
    ]
