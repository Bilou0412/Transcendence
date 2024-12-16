from django.db import models
from django.db.models import Q

class UserProfile(models.Model):
    user_id = models.IntegerField(unique=True)
    nb_game = models.IntegerField(default=0)
    nb_win = models.IntegerField(default=0)
    nb_losses = models.IntegerField(default=0)
    avg_duration = models.FloatField(default=0)
    friends = models.ManyToManyField('self', through='Friendship', symmetrical=False)
    
    def __str__(self) -> str:
        return f"User {self.user_id}"

class Friendship(models.Model):
    user_1 = models.ForeignKey('UserProfile', on_delete=models.CASCADE, related_name='friendship_user_1')
    user_2 = models.ForeignKey('UserProfile', on_delete=models.CASCADE, related_name='friendship_user_2')
    status = models.CharField(max_length=20, choices=[('pending', 'Pending'), ('accepted', 'Accepted')], default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('user_1', 'user_2')
    
    def __str__(self):
        return f"Friendship between {self.user_1} and {self.user_2} ({self.status})"

class Match(models.Model):
    player_1 = models.ForeignKey('UserProfile', on_delete=models.CASCADE, related_name='matches_as_player_1')
    player_2 = models.ForeignKey('UserProfile', on_delete=models.CASCADE, related_name='matches_as_player_2')
    created_at = models.DateTimeField(auto_now_add=True)
    match_start_time = models.DateTimeField()  # Doit toujours être fourni
    match_end_time = models.DateTimeField(null=True, blank=True) # Doit toujours être fourni
    score_player_1 = models.IntegerField(default=0)  # Ajouter une valeur par défaut
    score_player_2 = models.IntegerField(default=0)  # Ajouter une valeur par défaut

    def __str__(self):
        return f"Match {self.id}: {self.player_1.user_id} vs {self.player_2.user_id}"

class BlockedUser(models.Model):
    blocker = models.ForeignKey('UserProfile', on_delete=models.CASCADE, related_name='blocked_users')
    blocked = models.ForeignKey('UserProfile', on_delete=models.CASCADE, related_name='blocked_by')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('blocker', 'blocked')  # Empêche le doublon du blocage
        verbose_name = "Blocked User"
        verbose_name_plural = "Blocked Users"

    def __str__(self):
        return f"Block {self.blocker.user_id} blocked {self.blocked.user_id}"
