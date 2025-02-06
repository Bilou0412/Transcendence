console.log('chat.js loaded');

function loadChatPage() {
	const accessToken = sessionStorage.getItem('accessToken');
	if (!accessToken) {
		console.error('Access token not found');
		return;
	}
    console.log('Loading chat page');
	fetchFriendList(accessToken);
}
loadChatPage();
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
				const friendList = document.getElementById('friendList');
				friendList.innerHTML = '';
				friendIds.forEach(friendId => {
					const li = document.createElement('div');
					li.className = 'friend-item';
					
					const avatar = document.createElement('img');
					avatar.src = '../css/icon/rounded_login.png'; // Placeholder avatar
					avatar.alt = 'User Avatar';
					avatar.className = 'friend-avatar';
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
					const inviteButton = document.createElement('button');
					inviteButton.className = 'btn btn-invite';
					inviteButton.innerText = 'Invite';
					inviteButton.onclick = () => {
						inviteToChat(friendId);
					};
					const removeButton = document.createElement('button');
					removeButton.className = 'btn btn-remove';
					removeButton.innerText = 'Remove';
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
					
					userActions.appendChild(inviteButton);
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

function inviteToChat(friendId) {
	// Implement the function to invite a friend to chat
	console.log(`Inviting friend with ID ${friendId} to chat`);
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