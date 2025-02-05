function profileNav() {
	const accessToken = sessionStorage.getItem('accessToken');
	if (!accessToken) {
		console.error('Access token not found');
		return;
	}
	const userId = sessionStorage.getItem('userId');

	fetch('https://localhost:8443/auth/users/info/', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + accessToken
		},
		body: JSON.stringify({ user_ids: [userId] })
	})
	.then(response => response.json())
	.then(data => {
		const user = data[userId];
		document.getElementById('profile-username').innerText = user.username;
		document.getElementById('profile-id').innerText = user.id;
		fetchProfileImages(user.id, accessToken, ['profile-image']);
		fetchUserMatches(user.id, accessToken);
		fetchUserStatistics(user.id, accessToken);
		fetchUserFriends(user.id, accessToken); // Ensure this function is called correctly
		fetchFriendRequests();
		fetchFriendList(accessToken);
	})
	.catch(error => console.error('Error viewing profile:', error));
}

profileNav();

document.getElementById('search_bar').addEventListener('input', function(event) {
	const query = event.target.value;
	if (query.length > 0) {
		fetch(`https://localhost:8443/auth/search_user/?username=${query}`, {
			method: 'GET',
			headers: {
				'Content-Type': 'application/json',
				'Authorization': 'Bearer ' + sessionStorage.getItem('accessToken')
			}
		})
		.then(response => response.json())
		.then(data => {
			if (data.users) {
				console.log('Search results:', data.users);
				displaySearchResults(data.users);
			} else {
				console.error('No users found');
			}
		})
		.catch(error => console.error('Error searching users:', error));
	} else {
		clearSearchResults();
	}
});

function displaySearchResults(users) {
	const resultsContainer = document.getElementById('searchResults');
	resultsContainer.innerHTML = '';
	users.forEach(user => {
		const userElement = document.createElement('div');
		userElement.className = 'friend-item';
		
		const avatar = document.createElement('img');
		avatar.src = '../css/icon/rounded_login.png'; // Placeholder avatar
		avatar.alt = 'User Avatar';
		avatar.className = 'friend-avatar';
		
		const userInfo = document.createElement('div');
		userInfo.className = 'friend-info';
		const userName = document.createElement('div');
		userName.className = 'friend-name';
		userName.innerText = `${user.username} (#${user.id})`;
		userInfo.appendChild(userName);
		
		const userActions = document.createElement('div');
		userActions.className = 'friend-actions';
		const friendRequestButton = document.createElement('button');
		friendRequestButton.className = 'btn btn-friend-request';
		friendRequestButton.innerText = 'Send Friend Request';
		friendRequestButton.onclick = function () {
			sendFriendRequest(user.id);
		};
		userActions.appendChild(friendRequestButton);
		
		userElement.appendChild(avatar);
		userElement.appendChild(userInfo);
		userElement.appendChild(userActions);
		
		resultsContainer.appendChild(userElement);
	});
}

function clearSearchResults() {
	const resultsContainer = document.getElementById('searchResults');
	resultsContainer.innerHTML = '';
}

function fetchProfileImages(userId, accessToken, imageElementIds) {
    // Fetch and display profile images
}

function fetchUserMatches(userId, accessToken) {
    // Fetch and display user match history
}

function fetchUserStatistics(userId, accessToken) {
    // Fetch and display user statistics
}

function fetchUserFriends(userId, accessToken) {
    // Fetch and display user friends
}

function fetchFriendRequests() {
	const accessToken = sessionStorage.getItem('accessToken');
	fetch('https://localhost:8443/usermanagement/friends/listrequests/', {
		headers: {
			'Authorization': `Bearer ${accessToken}`
		}
	})
	.then(response => {
		if (!response.ok) {
			throw new Error('Network response was not ok');
		}
		return response.json();
	})
	.then(data => {
		console.log('Friend requests data:', data); // Debugging line
		const requestContainer = document.getElementById('requestResults');
		requestContainer.innerHTML = '';
		data.pending_requests.forEach(request => {
			const requestElement = document.createElement('div');
			requestElement.className = 'friend-item';
			
			const avatar = document.createElement('img');
			avatar.src = '../css/icon/rounded_login.png'; // Placeholder avatar
			avatar.alt = 'User Avatar';
			avatar.className = 'friend-avatar';
			
			const userInfo = document.createElement('div');
			userInfo.className = 'friend-info';
			const userName = document.createElement('div');
			userName.className = 'friend-name';
			userName.innerText = `Friend request from User ID: ${request}`;
			userInfo.appendChild(userName);
			
			const userActions = document.createElement('div');
			userActions.className = 'friend-actions';
			const acceptButton = document.createElement('button');
			acceptButton.className = 'btn btn-accept-request';
			acceptButton.innerText = 'Accept';
			acceptButton.onclick = function () {
				respondToFriendRequest(request, true);
				requestElement.remove();
			};
			const rejectButton = document.createElement('button');
			rejectButton.className = 'btn btn-reject-request';
			rejectButton.innerText = 'Reject';
			rejectButton.onclick = function () {
				respondToFriendRequest(request, false);
				requestElement.remove();
			};
			userActions.appendChild(acceptButton);
			userActions.appendChild(rejectButton);
			
			requestElement.appendChild(avatar);
			requestElement.appendChild(userInfo);
			requestElement.appendChild(userActions);
			
			requestContainer.appendChild(requestElement);
		});
	})
	.catch(error => console.error('Error fetching friend requests:', error));
}

function respondToFriendRequest(friendId, accept) {
	const accessToken = sessionStorage.getItem('accessToken');
	fetch('https://localhost:8443/usermanagement/friends/update/', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${accessToken}`
		},
		body: JSON.stringify({
			friend_id: friendId,
			status: accept ? 'accepted' : 'refused'
		})
	})
	.then(response => response.json())
	.then(data => {
		console.log(`Friend request ${accept ? 'accepted' : 'refused'}:`, data);
		alert(`Friend request ${accept ? 'accepted' : 'refused'} successfully!`);
		fetchFriendRequests(); // Refresh friend requests
	})
	.catch(error => {
		console.error(`Error responding to friend request:`, error);
		alert(`Failed to respond to friend request`);
	});
}

function sendFriendRequest(receiverId) {
	const accessToken = sessionStorage.getItem('accessToken');
	fetch('https://localhost:8443/usermanagement/friends/request/', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${accessToken}`
		},
		body: JSON.stringify({
			friend_id: receiverId
		})
	})
	.then(response => response.json())
	.then(data => {
		console.log('Friend request sent:', data);
		alert('Friend request sent successfully!');
	})
	.catch(error => {
		console.error('Error sending friend request:', error);
		alert('Failed to send friend request');
	});
}

function fetchFriendList(accessToken) {
	fetch('https://localhost:8443/usermanagement/friends/', {
		headers: {
			'Authorization': `Bearer ${accessToken}`
		}
	})
	.then(response => response.json())
	.then(data => {
		const friendIds = data.friends;
		if (friendIds.length > 0) {
			fetch('https://localhost:8443/auth/users/info/', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${accessToken}`
				},
				body: JSON.stringify({ user_ids: friendIds })
			})
			.then(response => response.json())
			.then(userData => {
				const friendList = document.getElementById('friendList');
				friendList.innerHTML = '';
				friendIds.forEach(friendId => {
					const li = document.createElement('div');
					li.className = 'friend-item';
					
					const avatar = document.createElement('img');
					avatar.src = '../css/icon/rounded_login.png'; // Placeholder avatar
					avatar.alt = 'User Avatar';
					avatar.className = 'friend-avatar';
					
					const userInfo = document.createElement('div');
					userInfo.className = 'friend-info';
					const userName = document.createElement('div');
					userName.className = 'friend-name';
					userName.innerText = `${userData[friendId].username} (#${friendId})`;
					userInfo.appendChild(userName);
					
					const userActions = document.createElement('div');
					userActions.className = 'friend-actions';
					const removeButton = document.createElement('button');
					removeButton.className = 'btn btn-remove';
					removeButton.innerText = 'Remove Friend';
					removeButton.onclick = () => {
						updateFriendRequest(friendId, 'refused');
						li.remove();
						};
					const blockButton = document.createElement('button');
					blockButton.className = 'btn btn-block';
					blockButton.innerText = 'Block';
					blockButton.onclick = () => {
						blockUser(friendId);
						li.remove();
					};
					
					userActions.appendChild(removeButton);
					userActions.appendChild(blockButton);
					li.appendChild(avatar);
					li.appendChild(userInfo);
					li.appendChild(userActions);
					friendList.appendChild(li);
				});
			})
			.catch(error => console.error('Error fetching friend details:', error));
		}
	})
	.catch(error => console.error('Error fetching friend list:', error));
}

function updateFriendRequest(friendId, status) {
	const accessToken = sessionStorage.getItem('accessToken');
	fetch('https://localhost:8443/usermanagement/friends/update/', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${accessToken}`
		},
		body: JSON.stringify({
			friend_id: friendId,
			status: status
		})
	})
	.then(response => response.json())
	.then(data => {
		console.log(`Friend request ${status}:`, data);
		alert(`Friend request ${status} successfully!`);
	})
	.catch(error => {
		console.error(`Error updating friend request to ${status}:`, error);
		alert(`Failed to ${status} friend request`);
	});
}

function blockUser(userId) {
	const accessToken = sessionStorage.getItem('accessToken');
	fetch('https://localhost:8443/usermanagement/block/request/', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${accessToken}`
		},
		body: JSON.stringify({
			user_to_block: userId
		})
	})
	.then(response => response.json())
	.then(data => {
		console.log('User blocked:', data);
		alert('User blocked successfully!');
	})
	.catch(error => {
		console.error('Error blocking user:', error);
		alert('Failed to block user');
	});
}

