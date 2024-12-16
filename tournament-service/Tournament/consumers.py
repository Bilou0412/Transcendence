import json
from channels.generic.websocket import AsyncWebsocketConsumer
from .models import Tournament, Player  # Modèles à créer plus tard

class TournamentConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Chaque tournoi aura son propre groupe
        self.tournament_id = self.scope['url_route']['kwargs']['tournament_id']
        self.tournament_group_name = f"tournament_{self.tournament_id}"

        # Rejoindre le groupe WebSocket
        await self.channel_layer.group_add(
            self.tournament_group_name,
            self.channel_name
        )

        # Accepter la connexion WebSocket
        await self.accept()

    async def disconnect(self, close_code):
        # Quitter le groupe WebSocket
        await self.channel_layer.group_discard(
            self.tournament_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        # Recevoir les données du client
        data = json.loads(text_data)
        username = data['username']

        # Ajouter le joueur au tournoi
        await self.add_player_to_tournament(username)

        # Envoyer un message de confirmation à tous les joueurs
        await self.channel_layer.group_send(
            self.tournament_group_name,
            {
                'type': 'player_joined',
                'message': f"{username} a rejoint le tournoi !"
            }
        )

    async def add_player_to_tournament(self, username):
        # Simulation d'ajout d'un joueur (remplace avec ton modèle)
        tournament = Tournament.objects.get(id=self.tournament_id)
        Player.objects.create(username=username, tournament=tournament)

    # Méthode pour envoyer un message à tous les clients
    async def player_joined(self, event):
        await self.send(text_data=json.dumps({
            'message': event['message']
        }))
