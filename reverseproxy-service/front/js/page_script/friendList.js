import { fetchProfileImages } from './utils.js';
import { inviteGame } from './home.js';
import { viewProfile } from './profile.js';


export function fetchFriendList(accessToken) {
	return fetch(`https://${window.location.host}/usermanagement/friends/`, {
		headers: {
			'Authorization': `Bearer ${accessToken}`
		}
	})
	.then(response => response.json())
	.then(data => {
		console.log('Friend list in fetch:', data.friends);
		return data.friends;
	})

	.catch(error => console.error('Error fetching friend list:', error));
}



function fetchUsersInfos(accessToken, friendIds) {
	return fetch(`https://${window.location.host}/auth/users/info/`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${accessToken}`
		},
		body: JSON.stringify({ user_ids: friendIds })
	})
	.then(response => response.json())
	.then(userData => {
		return userData;
	})
}

export function buildFriendList(accessToken, elementId, onClickHandler) {
    // Check if the container exists and is empty before building
    const container = document.getElementById(elementId);
    if (!container) {
        console.error('Friend list container not found:', elementId);
        return;
    }

    // Clear the container before adding new items
    container.innerHTML = '';
    console.log('Building friend list for container:', elementId);

    fetchFriendList(accessToken)
    .then(friendIds => {
        console.log('Friend list:', friendIds);
        if (!friendIds || friendIds.length === 0) {
            container.innerHTML = '<div class="friend-item">No friends found</div>';
            return;
        }

        return fetchUsersInfos(accessToken, friendIds)
        .then(userData => {
            fetchBlockedUsers(accessToken, blockedUserIds => {
                friendIds.forEach(friendId => {
                    // Create friend item container
                    const li = document.createElement('div');
                    li.className = 'friend-item';

                    // Create and setup avatar
                    const avatar = document.createElement('img');
                    avatar.className = 'friend-avatar';
                    avatar.id = `avatar-${friendId}`;
                    if (onClickHandler) {
                        avatar.onclick = function() {
                            onClickHandler(friendId);
                        };
                    }

                    // Create user info section
                    const userInfo = document.createElement('div');
                    userInfo.className = 'friend-info';
                    const userName = document.createElement('div');
                    userName.className = 'friend-name';
                    userName.innerText = `${userData[friendId].username} (#${friendId})`;
                    if (onClickHandler) {
                        userName.onclick = function() {
                            onClickHandler(friendId);
                        };
                    }
                    userInfo.appendChild(userName);

                    // Create actions section
                    const userActions = document.createElement('div');
                    userActions.className = 'friend-actions';

                    // Add appropriate buttons based on context
                    if (onClickHandler && onClickHandler.name === 'profileNav') {
                        // Profile view buttons
                        const removeButton = document.createElement('button');
                        removeButton.className = 'btn btn-remove';
                        removeButton.innerText = 'Remove Friend';
                        removeButton.onclick = () => {
                            updateFriendRequest(friendId, 'refused');
                            li.remove();
                        };
                        userActions.appendChild(removeButton);
                    } else {
                        // Chat/Game view buttons
                        const inviteButton = document.createElement('button');
                        inviteButton.className = 'btn btn-invite';
                        inviteButton.innerText = 'Invite';
                        inviteButton.onclick = () => {
                            inviteGame(friendId);
                        };

                        const viewProfileButton = document.createElement('button');
                        viewProfileButton.className = 'btn btn-view-profile';
                        viewProfileButton.innerText = 'View Profile';
                        viewProfileButton.onclick = () => {
                            viewProfile(friendId);
                        };

                        userActions.appendChild(inviteButton);
                        userActions.appendChild(viewProfileButton);
                    }

                    // Add block/unblock button
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
                    userActions.appendChild(blockButton);

                    // Assemble the friend item
                    li.appendChild(avatar);
                    li.appendChild(userInfo);
                    li.appendChild(userActions);
                    container.appendChild(li);
                });

                // Load profile images for all friends
                fetchProfileImages(friendIds, accessToken, friendIds.map(friendId => `avatar-${friendId}`));
            });
        });
    })
    .catch(error => {
        console.error('Error building friend list:', error);
        container.innerHTML = '<div class="friend-item">Error loading friends</div>';
    });
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
