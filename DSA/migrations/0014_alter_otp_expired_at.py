# Generated by Django 5.1.3 on 2024-12-05 16:56

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DSA', '0013_quiz_usersubmission_alter_otp_expired_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otp',
            name='expired_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 5, 17, 1, 46, 39592, tzinfo=datetime.timezone.utc)),
        ),
    ]
