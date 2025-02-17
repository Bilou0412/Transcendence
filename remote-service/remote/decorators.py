from functools import wraps
import httpx
from channels.exceptions import DenyConnection

def auth_token(func):
	@wraps(func)
	async def wrapper(self, *args, **kwargs):
		try:
			token = self.scope.get('query_string', b'').decode()
			if not token:
				raise DenyConnection("Authorization token missing")

			async with httpx.AsyncClient(timeout=5) as validateClient:
				validateResponse = await validateClient.post(
					'http://auth:8000/auth/token/validate/',
					headers={'Authorization': f'Bearer {token}'}
				)
			if validateResponse.status_code != 200:
				raise DenyConnection("Invalid authorization token")

			userData = validateResponse.json()
			self.userId = int(userData.get('id'))
			
			async with httpx.AsyncClient(timeout=5) as userInfosClient:
				userInfosResponse = await userInfosClient.post(
					'http://auth:8000/auth/users/info/',
					headers={'Authorization': f'Bearer {token}'},
					json={"user_ids": [self.userId]}
				)
			if userInfosResponse.status_code != 200:
				raise DenyConnection("Invalid authorization token")

			userData = userInfosResponse.json()
			self.username = userData.get(str(self.userId)).get('username')

			return await func(self, *args, **kwargs)
        
		except httpx.RequestError as exc:
			raise DenyConnection(f"Authentication service unreachable: {exc}")
		except Exception as exc:
			raise DenyConnection(f"Authentication failed: {exc}")

	return wrapper