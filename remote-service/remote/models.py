from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
import random
import time
from datetime import datetime
import httpx

class Player:
	def __init__ (self, id):
		self.id = id
		self.pos = {'x': 0, 'y': 0}
		self.dimension = {'w': 1, 'h': 5}

	def move (self, direction):
		self.pos['y'] += direction
		if self.pos['y'] + 2.5 > 15:
			self.pos['y'] = 15 - 2.5
		if self.pos['y'] - 2.5 < -15:
			self.pos['y'] = -15 + 2.5

class Ball:
	def __init__ (self):
		self.pos = {'x': 0, 'y': 0}
		self.velocity = 2
		self.direction = {'x': 0.1, 'y': 0.1}
	
	def move (self):
		# print(f"ball pos: {self.pos} direction: {self.direction}")
		self.pos['x'] += self.velocity * self.direction['x']
		self.pos['y'] += self.velocity * self.direction['y']


class Game:
	def __init__ (self, group_name):
		self.time = 0
		self.ball = Ball()
		self.players = {'left': None, 'right': None}
		self.group_name = group_name
		self.dimensions = {'w': 50, 'h': 30}
		self.score = {'left': 0, 'right': 0}
		self.status = False
		self.paused = False
		self.servSide = 'left'
		self.maxScore = 15
		self.hitLast = 'right'

	async def add_player (self, player):
		if self.players['left'] is None:
			self.players['left'] = player
		elif self.players['right'] is None:
			self.players['right'] = player
		else:
			print('Error: Game is full')
			return
		print(f'player {player.id} added at role {self.get_player_role(player.id)}')
		if self.players['left'] is not None and self.players['right'] is not None:
			time.sleep(5)
			await self.start()

	async def remove_player (self, role):
		if role not in self.players or self.players[role] is None:
			print(f'Error: No player to remove in role {role}')
			return
		print(f'removing player at role {role}')
		if self.status:
			self.paused = True
		self.status = False
		self.players[role] = None

	def get_player_role(self, player_id):
		for role, player in self.players.items():
			if player and player.id == player_id:
				return role
		return None  # Return None if no player with the given id is found

	async def start (self):
		if None in self.players.values():
			return
		if not self.paused:
			self.players['left'].pos = {'x': -24, 'y': 0}
			self.players['right'].pos = {'x': 24, 'y': 0}
			self.reset()
		else:
			self.ball.pos = {'x': 0, 'y': 0}
		self.time = datetime.now()
		await self.send_data({'type': 'assign_role'})
		await self.send_data({'type': 'start_game'})
		print('game started')
		self.status = True

	async def end (self):
		print('game ended')
		self.status = False
		if self.score['left'] == self.maxScore or self.score['right'] == self.maxScore:
			winner = 'left' if self.score['left'] == self.maxScore else 'right'
		else:
			winner = 'unfinished'
		await self.send_data( {
				'type': 'game_ended',
				'data': {
					'winner': winner
				}
			}
		)
		if winner == 'unfinished':
			self.score['left'] = self.score['right'] = 0
			return
		end_time = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
		start_time = self.time.strftime('%Y-%m-%dT%H:%M:%SZ')
		async with httpx.AsyncClient(timeout=5) as userManagerClient:
			userManagerResponse = await userManagerClient.post(
				'http://usermanagement:8000/usermanagement/matches/create/',
				json={
					'player_1_id': self.players['left'].id,
					'player_2_id': self.players['right'].id,
					'match_start_time': start_time,
					'match_end_time': end_time,
					'score_player_1': self.score['left'],
					'score_player_2': self.score['right'],
				}
			)
		print(f"fin de partie msg: {userManagerResponse.text}")
		self.score['left'] = self.score['right'] = 0

	async def send_data (self, data):
		await get_channel_layer().group_send(
			self.group_name, data)

	async def send_update(self):
		# print('sending update')
		await self.send_data({
			'type': 'game_update',
			'data': {
				'ball': self.ball.pos,
				'players': {
					'left': {
						'pos': self.players['left'].pos,
						'score': self.score['left']
					},
					'right': {
						'pos': self.players['right'].pos,
						'score': self.score['right']
					}
				}
			}
		})

	def reset (self):
		self.ball.pos = {'x': 0, 'y': 0}
		self.ball.direction = {'x': -0.1 if self.servSide == 'left' else 0.1, 'y': random.choice([-0.065, 0.065])}

	async def move_paddle (self, player_id, direction):
		print(f'moving paddle {direction}')
		role = self.get_player_role(player_id)
		if role is None:
			print(f'Error: Player with id {player_id} not found')
			return
		direction = 0.3 if direction == 'up' else -0.3
		self.players[role].move(direction)
	
	def handle_collision(self, paddle, potential_pos):
		max_angle = 0.4
		angle = max(-max_angle, min(max_angle, ((potential_pos['y'] - paddle.pos['y']) / (paddle.dimension['h'] / 2)) * max_angle))

		self.ball.direction['y'] = angle
		self.ball.direction['x'] *= -1

	async def update (self):
		try:
			left_paddle = self.players['left']
			right_paddle = self.players['right']

			potential_pos = {
				'x': self.ball.pos['x'] + self.ball.velocity * self.ball.direction['x'],
				'y': self.ball.pos['y'] + self.ball.velocity * self.ball.direction['y']
			}

			if  self.hitLast == 'right' and (potential_pos['x'] <= left_paddle.pos['x'] + left_paddle.dimension['w'] / 2 + 0.1) and (potential_pos['x'] >= left_paddle.pos['x'] - 1):
				print('ball x aligned with left paddle')
				print(f'ball y: {potential_pos["y"]} left paddle y: {left_paddle.pos["y"]} left paddle down edge y: {left_paddle.pos["y"] - left_paddle.dimension["h"] / 2} left paddle up edge y: {left_paddle.pos["y"] + left_paddle.dimension["h"] / 2}')
				if potential_pos['y'] > left_paddle.pos['y'] - left_paddle.dimension['h'] / 2 - 0.3 and potential_pos['y'] < left_paddle.pos['y'] + left_paddle.dimension['h'] / 2 + 0.3:
					print('ball y aligned with left paddle')
					self.hitLast = 'left'
					self.handle_collision(left_paddle, potential_pos)
			elif self.hitLast == 'left' and potential_pos['x'] >= right_paddle.pos['x'] - right_paddle.dimension['w'] / 2 - 0.1 and potential_pos['x'] <= right_paddle.pos['x'] + 1:
				print('ball x aligned with right paddle')
				print(f'ball y: {potential_pos["y"]} right paddle y: {right_paddle.pos["y"]} ')
				if potential_pos['y'] > right_paddle.pos['y'] - right_paddle.dimension['h'] / 2 - 0.3 and potential_pos['y'] < right_paddle.pos['y'] + right_paddle.dimension['h'] / 2 + 0.3:
					print('ball y aligned with right paddle')
					self.hitLast = 'right'
					self.handle_collision(right_paddle, potential_pos)
			
			# walls collision 
			if self.ball.pos['y'] <= -15 or self.ball.pos['y'] >= 15:
				self.ball.direction['y'] *= -1

			self.ball.move()

			# score
			if self.ball.pos['x'] <= left_paddle.pos['x'] - left_paddle.dimension['w'] - 1:
				self.score['left'] += 1
				self.servSide = 'left'
				self.reset()
			if self.ball.pos['x'] >= right_paddle.pos['x'] + right_paddle.dimension['w'] + 1:
				self.score['right'] += 1
				self.servSide = 'right'
				self.reset()
			

			await self.send_update()

			if self.score['left'] == self.maxScore or self.score['right'] == self.maxScore:
				await self.end()
		except Exception as e:
			print(f'update Error: {str(e)}')