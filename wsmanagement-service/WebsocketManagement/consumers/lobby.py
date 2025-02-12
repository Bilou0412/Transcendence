from channels.generic.websocket import AsyncWebsocketConsumer
from ..models import UserInfo
from ..decorators import auth_token
# from . import connected_users
from django.core.cache import cache
import json
import uuid

class LobbyConsumer(AsyncWebsocketConsumer):
	@auth_token
	async def connect(self):
		self.lobby_group_name = 'lobby'
		await self.channel_layer.group_add(
			self.lobby_group_name,
			self.channel_name
		)
		await self.accept()
		cache.set(self.userId, UserInfo(id=self.userId, username=self.username))
		connected_user_ids = cache.get('connected_user_ids', set())
		connected_user_ids.add(self.userId)
		cache.set('connected_user_ids', connected_user_ids)
		connected_users = cache.get_many(connected_user_ids)
		await self.channel_layer.group_send(
			self.lobby_group_name,
			{
				'type': 'list_user_connected',
				'users': [{'id': user.id, 'username': user.username} for user in connected_users.values()]
			}
		)

	@auth_token
	async def disconnect(self, close_code):
		cache.delete(self.userId)
		await self.channel_layer.group_discard(
			self.lobby_group_name,
			self.channel_name
		)
		connected_user_ids = cache.get('connected_user_ids', set())
		connected_user_ids.discard(self.userId)
		cache.set('connected_user_ids', connected_user_ids)
		connected_users = cache.get_many(connected_user_ids)
		await self.channel_layer.group_send(
			self.lobby_group_name,
			{
				'type': 'list_user_connected',
				'users': [{'id': user.id, 'username': user.username} for user in connected_users.values()]
			}
		)

	async def list_user_connected(self, event):
		users = event['users']
		await self.send(text_data=json.dumps({
			'type': 'list_user_connected',
			'users': users
		}))

	async def receive(self, text_data):
		data = json.loads(text_data)
		if 'invitee_id' in data:
			await self.handle_invite(data)
		else:
			# Handle other message types
			pass

	async def handle_invite(self, data):
		invitee_id = data['invitee_id']
		invite_code = str(uuid.uuid4())

		# Send invite code to the inviter
		# await self.send(text_data=json.dumps({
		# 	'type': 'invite_code',
		# 	'invite_code': invite_code,
		# 	'invitee_id': invitee_id
		# }))

		# Send invite code to the invitee
		await self.channel_layer.group_send(
			self.lobby_group_name,
			{
				'type': 'send_invite',
				'invite_code': invite_code,
				'inviter_id': self.userId,
				'invitee_id': invitee_id
			}
		)

	async def send_invite(self, event):
		invite_code = event['invite_code']
		inviter_id = event['inviter_id']
		invitee_id = event['invitee_id']

		if self.userId in [inviter_id, invitee_id]:
			await self.send(text_data=json.dumps({
				'type': 'invite_code',
				'invite_code': invite_code,
				'inviter_id': inviter_id,
				'invitee_id': invitee_id
			}))

	async def friend_request(self, event):
		sender_id = event['sender_id']
		receiver_id = event['receiver_id']

		# Ne notifier que le destinataire
		if self.userId == receiver_id:
			await self.send(text_data=json.dumps({
				'type': 'friend_request',
				'sender_id': sender_id,
				'receiver_id': receiver_id
			}))
