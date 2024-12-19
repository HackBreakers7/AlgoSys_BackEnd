# Generated by Django 5.1.3 on 2024-12-05 08:43

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DSA', '0004_alter_customuser_roll_no_alter_otp_expired_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='bio',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='customuser',
            name='links',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='roll_no',
            field=models.CharField(default='default_roll_no', max_length=20, unique=True),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='stream',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AlterField(
            model_name='otp',
            name='expired_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 5, 8, 48, 30, 603187, tzinfo=datetime.timezone.utc)),
        ),
    ]
