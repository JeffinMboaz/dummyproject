# Generated by Django 4.2.20 on 2025-03-29 15:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_booking'),
    ]

    operations = [
        migrations.AddField(
            model_name='booking',
            name='package_title',
            field=models.CharField(default=0, max_length=200),
            preserve_default=False,
        ),
    ]
