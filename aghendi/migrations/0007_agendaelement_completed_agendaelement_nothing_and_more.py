# Generated by Django 5.1.4 on 2024-12-19 16:18

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('aghendi', '0006_delete_useragendaelementstatus'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='agendaelement',
            name='completed',
            field=models.ManyToManyField(blank=True, related_name='flagged_completed', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='agendaelement',
            name='nothing',
            field=models.ManyToManyField(related_name='not_flagged', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='agendaelement',
            name='urgent',
            field=models.ManyToManyField(blank=True, related_name='flagged_urgent', to=settings.AUTH_USER_MODEL),
        ),
    ]
