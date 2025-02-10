import { fetchProfileImages } from './utils.js';

function profileNav(idToSearch) {
	const accessToken = sessionStorage.getItem('accessToken');
	if (!accessToken) {
		console.error('Access token not found');
		return;
	}

	fetch('https://localhost:8443/auth/users/info/', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + accessToken
		},
		body: JSON.stringify({ user_ids: [idToSearch] })
	})
	.then(response => response.json())
	.then(data => {
		const user = data[idToSearch];
		document.getElementById('profile-username').innerText = user.username;
		document.getElementById('profile-id').innerText = user.id;
		fetchProfileImages(user.id, accessToken, ['userIcon']);
		fetchUserMatches(user.id, accessToken);
		fetchUserStatistics(user.id, accessToken);
		fetchUserFriends(user.id, accessToken); // Ensure this function is called correctly
		fetchFriendRequests();
		fetchFriendList(accessToken);
		if (sessionStorage.getItem('userId') !== idToSearch) {
			document.getElementById('editBtn').style.display = 'none';
		}
	})
	.catch(error => console.error('Error viewing profile:', error));
}

if (sessionStorage.getItem('userId')) {
	console.log('ok');
	profileNav(sessionStorage.getItem('userId'));
}

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
	const resultsContainer = document.getElementById('searchResults-body');
	resultsContainer.innerHTML = '';
	users.forEach(user => {
		const userElement = document.createElement('div');
		userElement.className = 'friend-item';
		
		const avatar = document.createElement('img');
		// avatar.src = '../css/icon/rounded_login.png'; // Placeholder avatar
		// avatar.alt = 'User Avatar';
		avatar.className = 'friend-avatar';
		avatar.id = `search-avatar-${user.id}`;
		avatar.onclick = function () {
            profileNav(user.id);
        };
		
		const userInfo = document.createElement('div');
		userInfo.className = 'friend-info';
		const userName = document.createElement('div');
		userName.className = 'friend-name';
		userName.innerText = `${user.username} (#${user.id})`;
		userName.onclick = function () {
            profileNav(user.id);
        };
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
	fetchProfileImages(users.map(user => user.id), sessionStorage.getItem('accessToken'), users.map(user => `search-avatar-${user.id}`));
}

function clearSearchResults() {
	const resultsContainer = document.getElementById('searchResults-body');
	resultsContainer.innerHTML = '';
}

function fetchUserMatches(userId, accessToken) {
	console.log('Fetching user matches...');
	fetch(`https://localhost:8443/usermanagement/${userId}/matches/`, {
		method: 'GET',
		headers: {
			'Authorization': 'Bearer ' + accessToken
		}
	})
	.then(response => {
		if (response.status === 404) {
			console.log('No matches found');
			const historyTable = document.getElementById('history');
			while (historyTable.rows.length > 1) {
				historyTable.deleteRow(1);
			}
			const newRow = historyTable.insertRow();
			newRow.className = 'match';
			newRow.innerHTML = `
				<td colspan="8">No matches found</td>
			`;
			return;
		}
		if (!response.ok && response.status !== 404) {
			throw new Error('Network response was not ok');
		}
		return response.json();
	})
	.then(data => {
		if (!data) return; 

		const historyTable = document.getElementById('history');
		
		while (historyTable.rows.length > 1) {
            historyTable.deleteRow(1);
        }

		data.matches.forEach(match => {
			const newRow = historyTable.insertRow();
			newRow.className = 'match';
			newRow.innerHTML = `
				<td>${match.match_id}</td>
				<td>${match.player_1_id}</td>
				<td>${match.player_2_id}</td>
				<td>${match.start_time}</td>
				<td>${match.end_time}</td>
				<td>${match.score_player_1}</td>
				<td>${match.score_player_2}</td>
				<td>${match.created_at}</td>
			`;
			
		});
	})
	.catch(error => console.error('Error fetching user matches:', error));
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
		const requestContainer = document.getElementById('requestResults-body');
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
		if (!data) return;
		
		const friendIds = data.friends;
		if (friendIds.length > 0) {
			console.log('Friend list:', data);
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
				const friendList = document.getElementById('friendList-body');
				friendList.innerHTML = '';
				fetchBlockedUsers(accessToken, blockedUserIds => {
					friendIds.forEach(friendId => {
						const li = document.createElement('div');
						li.className = 'friend-item';
						
						const avatar = document.createElement('img');
						// avatar.src = '../css/icon/rounded_login.png'; // Placeholder avatar
						// avatar.alt = 'User Avatar';
						avatar.className = 'friend-avatar';
						avatar.id = `profile-avatar-${friendId}`;
						avatar.onclick = function () {
							profileNav(friendId);
						};
						
						const userInfo = document.createElement('div');
						userInfo.className = 'friend-info';
						const userName = document.createElement('div');
						userName.className = 'friend-name';
						userName.innerText = `${userData[friendId].username} (#${friendId})`;
						userName.onclick = function () {
							profileNav(friendId);
						};
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
						blockButton.className = 'btn';
						if (blockedUserIds.has(friendId)) {
							blockButton.innerText = 'Unblock';
							blockButton.onclick = () => {
								unblockUser(friendId);
								li.remove();
							};
						} else {
							blockButton.innerText = 'Block';
							blockButton.onclick = () => {
								blockUser(friendId);
								li.remove();
							};
						}
						
						userActions.appendChild(removeButton);
						userActions.appendChild(blockButton);
						li.appendChild(avatar);
						li.appendChild(userInfo);
						li.appendChild(userActions);
						friendList.appendChild(li);
					});
					console.log(friendIds.map(friendId => `profile-avatar-${friendId}`));
					fetchProfileImages(friendIds, accessToken, friendIds.map(friendId => `profile-avatar-${friendId}`));
				});
			})
			.catch(error => console.error('Error fetching friend details:', error));
		} else {
			fetchBlockedUsers(accessToken, blockedUserIds => {
				const friendList = document.getElementById('friendList-body');
				friendList.innerHTML = '';
				blockedUserIds.forEach(blockedId => {
					const li = document.createElement('div');
					li.className = 'friend-item';
				});
			});
		}
	})
	.catch(error => console.error('Error fetching friend list:', error));
}

function fetchBlockedUsers(accessToken, callback) {
	fetch('https://localhost:8443/usermanagement/block/', {
		headers: {
			'Authorization': `Bearer ${accessToken}`,
			'Content-Type': 'application/json'
		}
	})
	.then(response => response.json())
	.then(data => {
		const blockedUserIds = new Set(data.blocked_users);
		callback(blockedUserIds);
	})
	.catch(error => console.error('Error fetching blocked users:', error));
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

function unblockUser(userId) {
	const accessToken = sessionStorage.getItem('accessToken');
	fetch('https://localhost:8443/usermanagement/unblock/', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${accessToken}`
		},
		body: JSON.stringify({
			user_to_unblock: userId
		})
	})
	.then(response => response.json())
	.then(data => {
		console.log('User unblocked:', data);
		alert('User unblocked successfully!');
	})
	.catch(error => {
		console.error('Error unblocking user:', error);
		alert('Failed to unblock user');
	});
}

