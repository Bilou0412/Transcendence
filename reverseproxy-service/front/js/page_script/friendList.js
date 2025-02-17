import { fetchProfileImages, fetchFriendList, fetchUsersInfos } from './fetchData.js';
import { inviteGame } from './home.js';
import { viewProfile } from './profile.js';
import { sleep } from '../pong/resetBall.js';








export function buildFriendList(accessToken, elementId, onClickHandler) {
    // Check if the container exists and is empty before building
    const container = document.getElementById(elementId);
    if (!container) {
        console.error('Friend list container not found:', elementId);
        return;
    }

    // Clear the container before adding new items
    container.innerHTML = '';

    fetchFriendList(accessToken)
    .then(friendIds => {
        if (!friendIds || friendIds.length === 0) {
            container.innerHTML = '<div class="friend-item">No friends found</div>';
            return;
        }
        fetchUsersInfos(accessToken, friendIds)
        .then(userData => {
            fetchBlockedUsers(accessToken, blockedUserIds => {
                friendIds.forEach(friendId => {
                    // Create friend item container
                    const li = document.createElement('div');
                    li.className = 'friend-item';

                    // Create and setup avatar
                    const avatar = document.createElement('img');
                    avatar.className = 'friend-avatar offline';
                    avatar.id = `user-${friendId}`;
                    if (onClickHandler) {
                        avatar.onclick = function() {
                            onClickHandler(friendId);
                        };
                    }
                    // Créer la pastille de statut
                    const statusIndicator = document.createElement('div');
                    statusIndicator.className = 'status-indicator';

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
                    li.appendChild(statusIndicator);
                    li.appendChild(userInfo);
                    li.appendChild(userActions);
                    container.appendChild(li);
                });

                // Load profile images for all friends
                fetchProfileImages(friendIds, accessToken, friendIds.map(friendId => `user-${friendId}`));
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
			// console.log(`Friend request ${status}:`, data);
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
			// console.log('User blocked:', data);
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
			// console.log('User unblocked:', data);
			alert('User unblocked successfully!');
		})
		.catch(error => {
			console.error('Error unblocking user:', error);
			alert('Failed to unblock user');
		});
}

export async function changeFriendStatus(data) {
    // Get all user elements in the document
    const userElements = document.querySelectorAll('[id^="user-"]');

    // Convert data.users into a Set for quick lookup (ensuring IDs are strings)
    const onlineUsers = new Set(data.users.map(user => String(user.id)));

    for (const userElement of userElements) {
        const userId = userElement.id.replace('user-', ''); // Extract ID as string
        
        if (onlineUsers.has(userId)) {
            // User is online
            console.log('Changing status to online for:', userId);
            userElement.classList.remove('offline');
            userElement.classList.add('online');
        } else {
            // User is offline
            console.log('Changing status to offline for:', userId);
            userElement.classList.remove('online');
            userElement.classList.add('offline');
        }
    }
}

