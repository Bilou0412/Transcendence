import { fetchProfileImages } from './utils.js';

// export function fetchFriendList(accessToken, elementId, onClickHandler) {
// 	fetch(`https://${window.location.host}/usermanagement/friends/`, {
// 		headers: {
// 			'Authorization': `Bearer ${accessToken}`
// 		}
// 	})
// 	.then(response => response.json())

// 	.catch(error => console.error('Error fetching friend list:', error));
// }

export function fetchFriendList(accessToken, elementId, onClickHandler) {
	fetch(`https://${window.location.host}/usermanagement/friends/`, {
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
			fetch(`https://${window.location.host}/auth/users/info/`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${accessToken}`
				},
				body: JSON.stringify({ user_ids: friendIds })
			})
			.then(response => response.json())
			.then(userData => {
				const friendList = document.getElementById(elementId);
				friendList.innerHTML = '';
				fetchBlockedUsers(accessToken, blockedUserIds => {
					friendIds.forEach(friendId => {
						const li = document.createElement('div');
						li.className = 'friend-item';

						const avatar = document.createElement('img');
						avatar.className = 'friend-avatar';
						avatar.id = `profile-avatar-${friendId}`;
						avatar.onclick = function () {
							onClickHandler(friendId);
						};

						const userInfo = document.createElement('div');
						userInfo.className = 'friend-info';
						const userName = document.createElement('div');
						userName.className = 'friend-name';
						userName.innerText = `${userData[friendId].username} (#${friendId})`;
						userName.onclick = function () {
							onClickHandler(friendId);
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
	fetch(`https://${window.location.host}/usermanagement/block/`, {
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
	fetch(`https://${window.location.host}/usermanagement/friends/update/`, {
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
	fetch(`https://${window.location.host}/usermanagement/block/request/`, {
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
	fetch(`https://${window.location.host}/usermanagement/unblock/`, {
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
