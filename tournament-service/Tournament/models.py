from django.db import models

class Tournament(models.Model):
    name = models.CharField(max_length=100)

class Player(models.Model):
    username = models.CharField(max_length=50)
    tournament = models.ForeignKey(Tournament, on_delete=models.CASCADE, related_name='players')
