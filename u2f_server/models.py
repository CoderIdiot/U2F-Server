from __future__ import unicode_literals

from django.db import models

# Create your models here.
# Create your models here.
class User(models.Model):
	userName = models.CharField(max_length=32)
	challenge = models.CharField(max_length=64)
