from django.db import models
from django.core.validators import MinLengthValidator

# Create your models here.

class User(models.Model):
    id = models.BigAutoField(primary_key=True)
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=255)

    def __str__(self):
        return self.username

class Blog(models.Model):
    id = models.BigAutoField(primary_key=True)
    author_id = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.TextField(max_length=50, unique=True)
    body = models.TextField(max_length=300)

    def __str__(self):
            return f"{self.author_id}: {self.title}"
