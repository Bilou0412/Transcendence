from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
import random
from datetime import datetime

class Player:
	def __init__ (self, id):
		self.id = id
		self.pos = {'x': 0, 'y': 0}
		self.dimension = {'w': 0.6, 'h': 7}

	def move (self, direction):
		self.pos['y'] += direction
		if self.pos['y'] + 3.5 > 15:
			self.pos['y'] = 15 - 3.5
		if self.pos['y'] - 3.5 < -15:
			self.pos['y'] = -15 + 3.5

class Ball:
	def __init__ (self):
		self.pos = {'x': 0, 'y': 0}
		self.velocity = 2
		self.direction = {'x': 0.1, 'y': 0.1}
	
	def move (self):
		self.pos['x'] += self.velocity * self.direction['x']
		self.pos['y'] += self.velocity * self.direction['y']


class Game:
	def __init__ (self, group_name):
		self.time = 0
		self.ball = Ball()
		self.players = {'left': None, 'right': None}
		self.group_name = group_name
		self.score = {'left': 0, 'right': 0}
		self.status = False
		self.paused = False

	async def add_player (self, player):
		if self.players['left'] is None:
			self.players['left'] = player
		elif self.players['right'] is None:
			self.players['right'] = player
		else:
			print('Error: Game is full')
		print(f'player added at role {self.get_player_role(player.id)}')

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
		print(f'len players: {len([p for p in self.players.values() if p is not None])}')
		if None in self.players.values():
			return
		if not self.paused:
			self.reset()
		else:
			self.ball.pos = {'x': 0, 'y': 0}
		self.time = datetime.now()
		await self.send_data({'type': 'assign_role'})
		await self.send_data({'type': 'start_game'})
		self.status = True

	async def end (self):
		print('game ended')
		self.status = False
		if self.score['left'] == 10 or self.score['right'] == 10:
			winner = 'left' if self.score['left'] == 10 else 'right'
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
			print(userManagerResponse.text)
			print(userManagerResponse.text)
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
		self.ball.direction = {'x': random.choice([-0.1, 0.1]), 'y': random.choice([-0.1, 0.1])}
		self.players['left'].pos = {'x': -10, 'y': 0}
		self.players['right'].pos = {'x': 10, 'y': 0}

	async def move_paddle (self, player_id, direction):
		print(f'moving paddle {direction}')
		role = self.get_player_role(player_id)
		if role is None:
			print(f'Error: Player with id {player_id} not found')
			return
		direction = 0.5 if direction == 'up' else -0.5
		self.players[role].move(direction)

	def check_collision(self, paddle):
		# Ball properties
		ball_x, ball_y = self.ball.pos['x'], self.ball.pos['y']
		ball_radius = 0.5  # Assuming the self.ball has a radius of 1
	
		# Rectangle properties
		rect_x, rect_y = paddle.pos['x'], paddle.pos['y']
		rect_width, rect_height = paddle.dimension['w'], paddle.dimension['h']
	
		# Check collision with rectangle boundaries
		if (rect_x - rect_width * 0.5 <= ball_x + ball_radius <= rect_x + rect_width * 0.5 or
    		rect_x - rect_width * 0.5 <= ball_x - ball_radius <= rect_x + rect_width * 0.5) and \
    		(rect_y - rect_height * 0.5 <= ball_y + ball_radius <= rect_y + rect_height * 0.5 or
    		rect_y - rect_height * 0.5 <= ball_y - ball_radius <= rect_y + rect_height * 0.5):
			return True
		return False
			# return False
	
	def handle_collision(self, paddle):
		if self.check_collision(paddle):
			# Adjust ball position to prevent it from glitching into the paddle
			ball_x, ball_y = self.ball.pos['x'], self.ball.pos['y']
			ball_radius = 0.5  # Assuming the ball has a radius of 0.5

			rect_x, rect_y = paddle.pos['x'], paddle.pos['y']
			rect_width, rect_height = paddle.dimension['w'], paddle.dimension['h']

			# Determine the side of the collision and adjust position
			if ball_x < rect_x - rect_width / 2:
				self.ball.pos['x'] = rect_x - rect_width / 2 - ball_radius
				self.ball.direction['x'] *= -1
			elif ball_x > rect_x + rect_width / 2:
				self.ball.pos['x'] = rect_x + rect_width / 2 + ball_radius
				self.ball.direction['x'] *= -1

			if ball_y < rect_y - rect_height / 2:
				self.ball.pos['y'] = rect_y - rect_height / 2 - ball_radius
				self.ball.direction['y'] *= -1
			elif ball_y > rect_y + rect_height / 2:
				self.ball.pos['y'] = rect_y + rect_height / 2 + ball_radius
				self.ball.direction['y'] *= -1


	async def update (self):
		try:
			# print('updating')
			left_paddle = self.players['left']
			right_paddle = self.players['right']

			self.ball.move()

			
			# walls collision 
			if self.ball.pos['y'] <= -15 or self.ball.pos['y'] >= 15:
				self.ball.direction['y'] *= -1

			self.handle_collision(left_paddle)
			self.handle_collision(right_paddle)

			# score
			if self.ball.pos['x'] <= left_paddle.pos['x'] - left_paddle.dimension['w'] - 0.1:
				self.score['left'] += 1
				self.reset()
			if self.ball.pos['x'] >= right_paddle.pos['x'] + right_paddle.dimension['w'] + 0.1:
				self.score['right'] += 1
				self.reset()
			

			await self.send_update()

			if self.score['left'] == 10 or self.score['right'] == 10:
				await self.end()
		
		except Exception as e:
			print(f'update Error: {str(e)}')