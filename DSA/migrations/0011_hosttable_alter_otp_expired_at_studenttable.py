# Generated by Django 5.1.3 on 2024-12-05 13:19

import datetime
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DSA', '0010_alter_otp_expired_at'),
    ]

    operations = [
        migrations.CreateModel(
            name='HostTable',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('roll_no', models.IntegerField(unique=True)),
                ('name', models.CharField(max_length=100)),
                ('practical_no', models.IntegerField()),
                ('performance', models.DecimalField(decimal_places=2, max_digits=3)),
                ('mcqs', models.DecimalField(decimal_places=2, max_digits=3)),
                ('attendance', models.DecimalField(decimal_places=2, max_digits=3)),
                ('total', models.DecimalField(decimal_places=2, max_digits=4)),
                ('verified', models.BooleanField(default=False)),
            ],
        ),
        migrations.AlterField(
            model_name='otp',
            name='expired_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 5, 13, 24, 30, 848014, tzinfo=datetime.timezone.utc)),
        ),
        migrations.CreateModel(
            name='StudentTable',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('practical_no', models.IntegerField()),
                ('practical_name', models.CharField(max_length=100)),
                ('performance', models.DecimalField(decimal_places=2, max_digits=3)),
                ('mcqs', models.DecimalField(decimal_places=2, max_digits=3)),
                ('attendance', models.DecimalField(decimal_places=2, max_digits=3)),
                ('total', models.DecimalField(decimal_places=2, max_digits=4)),
                ('verified', models.BooleanField(default=False)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
