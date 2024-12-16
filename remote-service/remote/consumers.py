import json
from django.conf import settings
from channels.generic.websocket import AsyncWebsocketConsumer
from .decorators import auth_token
from .models import Game, Player
import asyncio

host, port = settings.CHANNEL_LAYERS['default']['CONFIG']['hosts'][0]
REDIS_URL = f"redis://{host}:{port}"

games = {}
game_tasks = {}
games_lock = asyncio.Lock()

async def game_loop(game):
	while True:
		if game.status:
			await game.update()
		await asyncio.sleep(0.016)  # Adjust the sleep time as needed

class PongConsumer(AsyncWebsocketConsumer):
	@auth_token
	async def connect(self):
		try:
			self.game_name = self.scope['url_route']['kwargs']['room_name']
			print(f"Connecting to group: {self.game_name}")

			async with games_lock:
				if self.game_name not in games:
					games[self.game_name] = Game(self.game_name)
					game_tasks[self.game_name] = asyncio.create_task(game_loop(games[self.game_name]))

				await games[self.game_name].add_player(Player(self.userId))
				self.game = games[self.game_name]

			await self.channel_layer.group_add(
				self.game_name,
				self.channel_name
			)
			await self.accept()

		except Exception as e:
			print(f'Connect Error: {str(e)}')

	@auth_token
	async def disconnect(self, close_code):
		try:
			async with games_lock:
				index = self.game.get_player_index_by_id(self.userId)
				await self.game.remove_player(index)
				if len(self.game.players) == 0:
					del games[self.game_name]
					game_tasks[self.game_name].cancel()
					del game_tasks[self.game_name]

			await self.channel_layer.group_discard(
			    self.game_name,
			    self.channel_name
			)

		except Exception as e:
			print(f'Disconnect Error: {str(e)}')

	async def receive(self, text_data):
		try:
			text_data_json = json.loads(text_data)
			event = text_data_json['event']
			data = text_data_json['data']
			# print(f"Received event: {event} with data: {data}")
			# Handle different types of events
			if event == 'paddle_moved':
				await self.handle_paddle_moved(data)
			elif event == 'start_game':
				await self.handle_start_game(data)
			elif event == 'end_game':
				await self.handle_end_game(data)
			elif event == 'score_update':
				await self.handle_score_update(data)
			else:
				await self.handle_unknown_event(event, data)
		
		except json.JSONDecodeError:
			await self.send_error('Invalid JSON')
		except KeyError as e:
			await self.send_error(f'Missing key: {str(e)}')
		except Exception as e:
			await self.send_error(f'Error: {str(e)}')

	async def handle_paddle_moved(self, data):
		try:
			if not self.game.status:
				return

			direction = data['direction']
			await self.game.move_paddle(self.userId, direction)
		
		except KeyError:
			await self.send_error('Missing key: direction')
		except Exception as e:
			await self.send_error(f'Error: {str(e)}')

	async def handle_start_game(self, data):
		print(f'game started: {self.game_name}')
		await games[self.game_name].start()

	async def handle_end_game(self, data):
		await self.channel_layer.group_send(
			self.game_name,
			{
				'type': 'game_ended',
				'data': data
			}
		)

	async def handle_unknown_event(self, event, data):
		await self.channel_layer.group_send(
			self.game_name,
			{
				'type': 'unknown_event',
				'data': {'event': event, 'data': data}
			}
		)

	async def send_error(self, message):
		await self.send(text_data=json.dumps({
			'event': 'error',
			'data': {'message': message}
		}))

	async def paddle_moved(self, event):
		await self.send(text_data=json.dumps({
			'event': 'paddle_moved',
			'data': event['data']
		}))

	async def start_game(self, event):
		await self.send(text_data=json.dumps({
			'event': 'start_game',
			# 'data': event['data']
		}))

	async def assign_role(self, event):
		index = self.game.get_player_index_by_id(self.userId)
		await self.send(text_data=json.dumps({
			'event': 'assign_role',
			'data': 'left' if index == 0 else 'right'
		}))

	async def game_ended(self, event):
		await self.send(text_data=json.dumps({
			'event': 'game_ended',
			'data': event['data']
		}))

	async def game_update(self, event):
		await self.send(text_data=json.dumps({
			'event': 'game_update',
			'data': event['data']
		}))

	async def game_reset(self, event):
		await self.send(text_data=json.dumps({
			'event': 'game_reset',
			'data': event['data']
		}))

	async def unknown_event(self, event):
		await self.send(text_data=json.dumps({
			'event': 'unknown_event',
			'data': event['data']
		}))
