# -*- coding: utf-8 -*-
# Generated by Django 1.9.1 on 2016-01-18 08:45
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('userName', models.CharField(max_length=32)),
                ('challenge', models.CharField(max_length=64)),
            ],
        ),
    ]
