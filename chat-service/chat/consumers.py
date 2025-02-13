from channels.generic.websocket import AsyncWebsocketConsumer
import json
import httpx
from channels.db import database_sync_to_async
from .decorators import auth_token
from .models import Conversation, DirectMessage
from channels.exceptions import DenyConnection

class ChatConsumer(AsyncWebsocketConsumer):
    @auth_token
    async def connect(self, tokenVal):
        try:
            self.chatId = self.scope['url_route']['kwargs']['chat_id']

            self.participants = sorted([self.userId, int(self.chatId)])
            self.chat_group_name = f'{self.participants[0]}_{self.participants[1]}'
            
            await self.validate_user_and_friends(tokenVal)
            self.conversation = await self.get_conversation()

            # # Check for existing connection and close it
            # existing_channels = await self.channel_layer.group_channels(self.chat_group_name)
            # for channel in existing_channels:
            #     if channel != self.channel_name:
            #         await self.channel_layer.send(channel, {
            #             'type': 'disconnect_old_connection'
            #         })


            await self.channel_layer.group_add(
                self.chat_group_name,
                self.channel_name
            )
            
            await self.accept()
            print('Connected')
            messages = await self.get_message_history(self.conversation)
            await self.send(text_data=json.dumps({
                'type': 'message_history',
                'messages': messages
            }))

        except Exception as e:
            print(f'Error in connect: {e}')
            await self.close()

    async def disconnect_old_connection(self, event):
        await self.close()


    async def validate_user_and_friends(self, tokenVal):
        otherUserId = int(self.chatId)

        if self.userId == otherUserId:
            raise DenyConnection("User cannot chat with self")

        async with httpx.AsyncClient(timeout=5) as friendshipClient:
            friendshipResponse = await friendshipClient.get(
				'http://usermanagement:8000/usermanagement/block/',
				headers={'Authorization': f'Bearer {tokenVal}'}
			)
        blocked_users = friendshipResponse.json()
        if (friendshipResponse.status_code == 200) and (otherUserId in blocked_users['blocked_users']):
            raise  DenyConnection("User blocked")

        async with httpx.AsyncClient(timeout=5) as friendshipClient:
            friendshipResponse = await friendshipClient.get(
				'http://usermanagement:8000/usermanagement/friends/',
				headers={'Authorization': f'Bearer {tokenVal}'}
			)
        friends = friendshipResponse.json()
        if friendshipResponse.status_code != 200 or otherUserId not in friends['friends']:
            raise  DenyConnection("Users not friend")

    @auth_token
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.chat_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message = data.get('message', '').strip()

            # if not message:
            #     await self.send(text_data=json.dumps({
            #         'type': 'error',
            #         'message': 'Empty message'
            #     }))
            #     return

            timestamp = await self.create_message(self.conversation, self.username, message)

            await self.channel_layer.group_send(
                self.chat_group_name,
                {
                    'type': 'chat_message',
                    'message': message,
                    'sender': self.username,
                    'timestamp': timestamp
                }
            )

        except Exception as e:
            print(f'Error in receive: {e}')
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'An error occurred'
            }))

    async def chat_message(self, event):
        message = event['message']
        sender = event['sender']
        timestamp = event['timestamp']
        print(f"Message: {message}, Sender: {sender}, Timestamp: {timestamp} self.username: {self.username}")
        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message': message,
            'sender': sender,
            'timestamp': timestamp
        }))


    async def get_conversation(self):
        try:
            conversation, created = await Conversation.objects.aget_or_create(
                participant1=self.participants[0],
                participant2=self.participants[1]
            )
            return conversation

        except Exception as e:
            print(f'Error in get_conversation: {e}')
            raise

    @database_sync_to_async
    def get_message_history(self, conversation):
        try:
            messages = DirectMessage.objects.filter(conversation=conversation).order_by('timestamp')
            return [{'sender': message.sender, 'content': message.content, 'timestamp': message.timestamp.isoformat()} for message in messages]
        except Exception as e:
            print(f'Error in get_message_history: {e}')
            return []


    @database_sync_to_async
    def create_message(self, conversation, sender, content):
        try:
            DirectMessage.objects.create(conversation=conversation, sender=sender, content=content)
            return DirectMessage.objects.last().timestamp.isoformat()            
        except Exception as e:
            print(f'Error in create_message: {e}')
            raise
