from django.db import models
from google.cloud import datastore

client = datastore.Client()


class User(models.Model):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)


class Image(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    image_type = models.CharField(max_length=50)
    image_size = models.IntegerField(default=0)
    url = models.URLField()
