# Generated by Django 5.1.4 on 2024-12-18 20:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('aghendi', '0003_alter_agendaelement_deadline_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='agendaelement',
            name='status',
            field=models.CharField(choices=[('active', 'Active'), ('expired', 'Expired')], default='active', max_length=20),
        ),
    ]
