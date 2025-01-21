from channels.generic.websocket import AsyncWebsocketConsumer
from django.core.cache import cache
import json
import uuid

class InviteConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user_id = self.scope['user'].id
        self.lobby_group_name = f"user_{self.user_id}"
        
        await self.channel_layer.group_add(
            self.lobby_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.lobby_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        if data['type'] == 'invite_to_game':
            sender_id = data['sender_id']
            opponent_ids = data['opponent_ids']  # Liste des utilisateurs à inviter
            await self.invite_to_game(sender_id, opponent_ids)
        elif data['type'] == 'accept_invitation':
            await self.accept_invitation(data['invite_key'])

    async def invite_to_game(self, sender_id, opponent_ids):
        invite_key = str(uuid.uuid4())
        cache.set(invite_key, {'inviter': sender_id, 'opponents': opponent_ids})
        for opponent_id in opponent_ids:
            await self.channel_layer.group_send(
                f"user_{opponent_id}",
                {
                    'type': 'game_invitation',
                    'invite_key': invite_key,
                    'inviter': sender_id,
                    'opponent': opponent_id
                }
            )

    async def accept_invitation(self, invite_key):
        # Récupérer l'invitation du cache
        invitation = cache.get(invite_key)
        if not invitation:
            return  # Invitation invalide ou expirée
        
        inviter_id = invitation['inviter']

        # Notifier l'invitant que l'utilisateur a accepté
        await self.channel_layer.group_send(
            f"user_{inviter_id}",
            {
                'type': 'invitation_accepted',
                'invite_key': invite_key,
                'accepter': self.user_id  # Celui qui accepte
            }
        )

    async def game_invitation(self, event):
        invite_key = event['invite_key']
        inviter = event['inviter']
        opponent = event['opponent']
        if self.user_id == opponent:
            await self.send(text_data=json.dumps({
                'type': 'game_invitation',
                'invite_key': invite_key,
                'inviter': inviter,
                'opponent': opponent
            }))

    async def invitation_accepted(self, event):
        invite_key = event['invite_key']
        accepter = event['accepter']
        await self.send(text_data=json.dumps({
            'type': 'invitation_accepted',
            'invite_key': invite_key,
            'accepter': accepter
        }))
