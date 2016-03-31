from __future__ import unicode_literals

from django.db import models

# Create your models here.

class User(models.Model):
	userName = models.CharField(max_length=32, primary_key=True)
	challenge = models.CharField(max_length=64)
	public_key = models.CharField(max_length=512, blank=True)
	key_handle = models.CharField(max_length=512, blank=True)
