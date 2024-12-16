let ball;
let paddle1;
let paddle2;
let playerRole = null;
let gameStarted = false;
let scoreLeft = 0;
let scoreRight = 0;
let intervalId = null;

let remoteWs = null;
let globalSocket = null;
let chatSocket = null;

function initThreeJs() {
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer();
    renderer.setSize(window.innerWidth, window.innerHeight);
    document.getElementById('threejs-container').appendChild(renderer.domElement);

    // Create the inside background
    const backgroundGeometry = new THREE.PlaneGeometry(20, 30);
    const backgroundMaterial = new THREE.MeshBasicMaterial({ color: 0x0000ff }); // Blue color
    const background = new THREE.Mesh(backgroundGeometry, backgroundMaterial);
    background.position.z = -1; // Position it behind the game objects
    scene.add(background);

    const paddleWidth = 0.6, paddleHeight = 7;
    const geometry = new THREE.BoxGeometry(paddleWidth, paddleHeight, 1);
    const material = new THREE.MeshBasicMaterial({ color: 0x00ff00 });
    paddle1 = new THREE.Mesh(geometry, material);
    paddle2 = new THREE.Mesh(geometry, material);
    scene.add(paddle1);
    scene.add(paddle2);

    paddle1.position.x = -10;
    paddle2.position.x = 10;

    const ballGeometry = new THREE.SphereGeometry(0.5, 32, 32);
    const ballMaterial = new THREE.MeshBasicMaterial({ color: 0xff0000 });
    ball = new THREE.Mesh(ballGeometry, ballMaterial);
    scene.add(ball);

    camera.position.z = 30;

    function animate() {
        requestAnimationFrame(animate);
        renderer.render(scene, camera);
    }
    animate();
}

function connectWebSocket(accessToken, username, userId) {
    globalSocket = new WebSocket(`ws://127.0.0.1:8005/ws/lobby/`, [`Bearer_${accessToken}`]);
    globalSocket.onopen = () => {
        console.log('WebSocket connection opened');
    };
    globalSocket.onmessage = event => {
        console.log('Received message:', event.data);
    };
    globalSocket.onclose = () => {
        console.log('WebSocket connection closed');
    };
}

function showMainMenu() {
    document.getElementById('login-signup').classList.remove('active');
    document.getElementById('main-menu').classList.add('active');
    document.getElementById('profile-info').classList.remove('active');
    document.getElementById('matches-info').classList.remove('active');
    document.getElementById('settings-info').classList.remove('active');
    document.getElementById('chat-interface').classList.remove('active');
    document.getElementById('threejs-container').classList.remove('active');
}

function showChat() {
    document.getElementById('profile-info').classList.remove('active');
    document.getElementById('matches-info').classList.remove('active');
    document.getElementById('settings-info').classList.remove('active');
    document.getElementById('chat-interface').classList.add('active');
    document.getElementById('duel-elements').classList.remove('active');
    document.getElementById('threejs-container').classList.remove('active');
}

function startChat() {
    const userId = document.getElementById('chat-user-id').value.trim();
    const accessToken = sessionStorage.getItem('accessToken');
    if (userId && accessToken) {
        if (chatSocket) {
            chatSocket.close();
        }
        chatSocket = new WebSocket(`ws://localhost:8001/ws/chat/${userId}/`, ['Bearer_' + accessToken]);

        chatSocket.onopen = () => {
            console.log('Direct Message WebSocket connection opened');
            const statusElement = document.createElement('div');
            statusElement.textContent = `Connected to direct messages with user ${userId}`;
            document.getElementById('chat-messages').appendChild(statusElement);
        };

        chatSocket.onmessage = event => {
            const message = JSON.parse(event.data);

            if (message.type === 'message_history') {
                message.messages.forEach(msg => {
                    const messageElement = document.createElement('div');
                    messageElement.textContent = `${msg.sender}: ${msg.content}`;
                    document.getElementById('chat-messages').appendChild(messageElement);
                });
            } else if (message.type === 'chat_message') {
                const messageElement = document.createElement('div');
                messageElement.textContent = `${message.sender}: ${message.message}`;
                document.getElementById('chat-messages').appendChild(messageElement);
            }
        };

        chatSocket.onclose = () => {
            console.log('Chat WebSocket connection closed');
        };
    } else {
        alert('Please enter a valid User ID and make sure you are logged in.');
    }
}

function sendChatMessage() {
    const messageInput = document.getElementById('chat-message-input');
    const message = messageInput.value.trim();
    if (chatSocket && message) {
        chatSocket.send(JSON.stringify({ message }));
        messageInput.value = '';
    } else {
        alert('Please enter a message to send.');
    }
}

function searchGame() {
    initThreeJs();
    document.getElementById('duel-elements').classList.add('active');
    document.getElementById('threejs-container').classList.add('active');
    document.getElementById('settings-info').classList.remove('active');
    document.getElementById('profile-info').classList.remove('active');
    document.getElementById('matches-info').classList.remove('active');
    document.getElementById('chat-interface').classList.remove('active');
    const accessToken = sessionStorage.getItem('accessToken');
    if (accessToken) {
        remoteWs = new WebSocket('ws://localhost:8003/ws/pong/key/', ['Bearer_' + accessToken]);
        remoteWs.onopen = function () {
            console.log('Remote WebSocket connection established');
        };

        remoteWs.onmessage = function (event) {
            const message = JSON.parse(event.data);
            console.log('Received message:', message);
            if (message.event === 'assign_role') {
                playerRole = message.data;
                console.log('Assigned role:', playerRole);
            }
            if (message.event === 'game_update') {
                ball.position.x = message.data.ball.x;
                ball.position.y = message.data.ball.y;
                paddle1.position.y = message.data.players.left.pos.y;
                paddle2.position.y = message.data.players.right.pos.y;
                if (scoreLeft !== message.data.players.left.score || scoreRight !== message.data.players.right.score) {
                    scoreLeft = message.data.players.left.score;
                    scoreRight = message.data.players.right.score;
                    document.getElementById('score-left').textContent = scoreLeft;
                    document.getElementById('score-right').textContent = scoreRight;
                }
            }
            if (message.event === 'start_game') {
                gameStarted = true;
                console.log('Game started');
                if (!intervalId) {
                    intervalId = setInterval(sendPaddleMovement, 10); // Check and send paddle movement every 10ms
                }
            }
            if (message.event === 'game_ended') {
                gameStarted = false;
                if (message.data.winner === playerRole) {
                    alert('You won!');
                } else if (message.data.winner !== 'unfinished') {
                    alert('You lost!');
                }
                resetGame();
                console.log('Game ended');
                clearInterval(intervalId);
                intervalId = null;
            }
        };

        remoteWs.onclose = function () {
            console.log('WebSocket connection closed');
        };

    } else {
        console.error('No auth token available');
    }
}

document.getElementById('start-game-button').addEventListener('click', function () {
    if (remoteWs.readyState === WebSocket.OPEN) {
        remoteWs.send(JSON.stringify({ event: 'start_game', data: null }));
        console.log('Sent start_game message to WebSocket server');
    } else {
        console.log('WebSocket connection is not open');
    }
});

function viewProfile() {
    const accessToken = sessionStorage.getItem('accessToken');
    const userId = sessionStorage.getItem('userId');
    console.log(JSON.stringify({ user_ids: [userId] }));
    fetch('http://127.0.0.1:8000/api/auth/users/info/', {
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
            document.getElementById('profile-username').innerText = `Username: ${user.username}`;
            document.getElementById('profile-email').innerText = `Email: ${user.email}`;
            document.getElementById('profile-info').classList.add('active');
            document.getElementById('matches-info').classList.remove('active');
            document.getElementById('duel-elements').classList.remove('active');
            document.getElementById('settings-info').classList.remove('active');
            document.getElementById('threejs-container').classList.remove('active');
            fetchProfileImages(user.id, accessToken, ['profile-image']);
            fetchUserMatches(user.id, accessToken);
        })
        .catch(error => console.error('Error viewing profile:', error));
}

function fetchProfileImages(userIds, accessToken, imageElementIds) {
    const cacheBuster = new Date().getTime(); // Generate a unique timestamp
    fetch(`http://127.0.0.1:8002/api/media/profile-images/?cb=${cacheBuster}`, {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + accessToken,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ user_ids: userIds })
    })
        .then(response => response.json())
        .then(images => {
            images.forEach((image, index) => {
                if (image.error) {
                    console.error(`Error fetching profile image for user ${image.id}: ${image.error}`);
                } else {
                    // const imageUrl = URL.createObjectURL(image.image);
                    console.log(image);
                    const imgElement = document.getElementById(imageElementIds[index]);
                    imgElement.src = image.image_url;
                    imgElement.alt = `Image ${image.id}`;
                    imgElement.type = image.content_type;

                }
            });
        })
        .catch(error => console.error('Error fetching profile images:', error));
}

function fetchUserMatches(userId, accessToken) {
    fetch(`http://127.0.0.1:8004/user/${userId}/matches/`, {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + accessToken
        }
    })
        .then(response => {
            if (response.status === 404) {
                const matchesList = document.getElementById('matches-list');
                matchesList.innerHTML = '<p>No matches found</p>';
                document.getElementById('matches-info').classList.add('active');
                throw new Error('No matches found');
            }
            if (!response.ok && response.status !== 404) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            const matchesList = document.getElementById('matches-list');
            matchesList.innerHTML = '';
            data.matches.forEach(match => {
                const matchElement = document.createElement('div');
                matchElement.className = 'match';
                matchElement.innerHTML = `
                <p>Match ID: ${match.match_id}</p>
                <p>Player 1 ID: ${match.player_1_id}</p>
                <p>Player 2 ID: ${match.player_2_id}</p>
                <p>Start Time: ${match.start_time}</p>
                <p>End Time: ${match.end_time}</p>
                <p>Score Player 1: ${match.score_player_1}</p>
                <p>Score Player 2: ${match.score_player_2}</p>
                <p>Created At: ${match.created_at}</p>
            `;
                matchesList.appendChild(matchElement);
            });
            document.getElementById('matches-info').classList.add('active');
        })
        .catch(error => console.error('Error fetching user matches:', error));
}

function showSettings() {
    document.getElementById('settings-info').classList.add('active');
    document.getElementById('profile-info').classList.remove('active');
    document.getElementById('threejs-container').classList.remove('active');
    document.getElementById('duel-elements').classList.remove('active');
    document.getElementById('matches-info').classList.remove('active');
    const accessToken = sessionStorage.getItem('accessToken');
    const userId = sessionStorage.getItem('userId');
    fetchProfileImages(userId, accessToken, ['settings-profile-image']);
}

document.getElementById('update-profile-form').addEventListener('submit', async function (event) {
    event.preventDefault();
    const accessToken = sessionStorage.getItem('accessToken');
    const currentUsername = sessionStorage.getItem('username');
    const currentEmail = document.getElementById('profile-email').innerText.split(': ')[1];
    const newUsername = document.getElementById('update-username').value || currentUsername;
    const newEmail = document.getElementById('update-email').value || currentEmail;

    try {
        const response = await fetch('http://127.0.0.1:8000/api/auth/update/', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + accessToken
            },
            body: JSON.stringify({ username: newUsername, email: newEmail })
        });
        const data = await response.json();
        if (response.ok) {
            sessionStorage.setItem('username', data.username);
            document.getElementById('profile-username').innerText = `Username: ${data.username}`;
            document.getElementById('profile-email').innerText = `Email: ${data.email}`;
            alert('Profile updated successfully.');
        } else {
            alert('Failed to update profile. Please try again.');
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        alert('Failed to update profile. Please try again.');
    }
});

document.getElementById('upload-image-form').addEventListener('submit', async function (event) {
    event.preventDefault();
    const accessToken = sessionStorage.getItem('accessToken');
    const userId = sessionStorage.getItem('userId');
    const fileInput = document.getElementById('upload-image');
    const formData = new FormData();
    formData.append('image', fileInput.files[0]);

    try {
        const response = await fetch('http://127.0.0.1:8002/api/media/upload/', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + accessToken
            },
            body: formData
        });
        if (response.ok) {
            alert('Image uploaded successfully.');
            fetchProfileImages(userId, accessToken, 'settings-profile-image');
        } else {
            alert('Failed to upload image. Please try again.');
        }
    } catch (error) {
        console.error('Error uploading image:', error);
        alert('Failed to upload image. Please try again.');
    }
});

document.getElementById('change-password-form').addEventListener('submit', async function (event) {
    event.preventDefault();
    const accessToken = sessionStorage.getItem('accessToken');
    const oldPassword = document.getElementById('old-password').value;
    const newPassword = document.getElementById('new-password').value;

    try {
        const response = await fetch('http://127.0.0.1:8000/api/auth/password/update/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + accessToken
            },
            body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
        });
        if (response.ok) {
            alert('Password changed successfully.');
        } else {
            alert('Failed to change password. Please try again.');
        }
    } catch (error) {
        console.error('Error changing password:', error);
        alert('Failed to change password. Please try again.');
    }
});

window.addEventListener('beforeunload', function () {
    if (remoteWs) {
        remoteWs.close();
    }
    if (globalSocket) {
        globalSocket.close();
    }
    if (chatSocket) {
        chatSocket.close();
    }
    // sessionStorage.removeItem('accessToken');
    // sessionStorage.removeItem('username');
    // sessionStorage.removeItem('userId');
});

// Check if the user is already logged in
window.onload = function () {
    const accessToken = sessionStorage.getItem('accessToken');
    const username = sessionStorage.getItem('username');
    const userId = sessionStorage.getItem('userId');
    if (accessToken && username && userId) {
        connectWebSocket(accessToken, username, userId);
        showMainMenu();
    } else {
        document.getElementById('login-signup').classList.add('active');
    }
};
let keysPressed = {};

window.addEventListener('keydown', function (event) {
    keysPressed[event.key] = true;
    sendPaddleMovement();
});

window.addEventListener('keyup', function (event) {
    keysPressed[event.key] = false;
    sendPaddleMovement();
});

window.addEventListener('blur', function () {
    keysPressed = {};
    sendPaddleMovement();
});

function sendPaddleMovement() {
    if (remoteWs && remoteWs.readyState === WebSocket.OPEN) {
        let direction = 0;
        if (keysPressed['w']) {
            direction = 'up';
        } else if (keysPressed['s']) {
            direction = 'down';
        }
        if (direction !== 0) {
            // console.log('Sending paddle movement:', direction);
            remoteWs.send(JSON.stringify({
                event: 'paddle_moved',
                data: { direction: direction, role: playerRole }
            }));
        }
    }
}


function resetGame() {
    ball.position.set(0, 0, 0);
    ballDirection = { x: 0.1, y: 0.1 };
    paddle1.position.y = 0;
    paddle2.position.y = 0;
    scoreLeft = 0;
    scoreRight = 0;
    document.getElementById('score-left').textContent = scoreLeft;
    document.getElementById('score-right').textContent = scoreRight;
}

function connectWebSocket(accessToken, username, userId) {
    const userList = document.getElementById('user-list');
    const friendRequestList = document.getElementById('friend-request-list');
    const socket = new WebSocket(`ws://localhost:8005/ws/lobby/`, [`Bearer_${accessToken}`]);
    globalSocket = socket;

    socket.onmessage = function (event) {
        const data = JSON.parse(event.data);
        console.log('Received WebSocket message:', data);

        switch (data.type) {
            case 'list_user_connected':
                handleUserList(data, userList, userId, socket);
                break;
            case 'invite_code':
                displayInviteCode(data);
                break;
            case 'friend_request':
                handleFriendRequest(data, friendRequestList);
                break;
            default:
                console.log('Unhandled message type:', data.type);
        }
    };

    socket.onopen = function () {
        console.log('WebSocket connection established');
    };

    socket.onclose = function () {
        console.log('WebSocket connection closed');
    };

    socket.onerror = function (error) {
        console.error('WebSocket error:', error);
    };
}

function handleUserList(data, userList, currentUserId, socket) {
    userList.innerHTML = '';
    data.users
        .filter(user => user.id !== currentUserId)
        .forEach(user => {
            const li = document.createElement('li');
            li.classList.add('user-item');

            const userInfo = document.createElement('span');
            userInfo.textContent = `${user.username} (ID: ${user.id})`;

            const userActions = document.createElement('div');
            userActions.classList.add('user-actions');

            const inviteButton = document.createElement('button');
            inviteButton.textContent = 'Invite';
            inviteButton.onclick = function () {
                sendInvite(user.id, socket);
            };

            const friendRequestButton = document.createElement('button');
            friendRequestButton.textContent = 'Send Friend Request';
            friendRequestButton.onclick = function () {
                sendFriendRequest(user.id);
            };

            userActions.appendChild(inviteButton);
            userActions.appendChild(friendRequestButton);

            li.appendChild(userInfo);
            li.appendChild(userActions);
            userList.appendChild(li);
        });
}

function sendInvite(inviteeId, socket) {
    socket.send(JSON.stringify({
        invitee_id: inviteeId
    }));
}

function sendFriendRequest(receiverId) {
    if (!globalSocket) {
        console.error('WebSocket not connected');
        return;
    }

    fetch('http://127.0.0.1:8004/user/friends/request/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${sessionStorage.getItem('accessToken')}`
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

function handleFriendRequest(data, friendRequestList) {
    const requestItem = document.createElement('li');
    requestItem.classList.add('friend-request');

    const requestText = document.createElement('span');
    requestText.textContent = `Friend request from User ID: ${data.sender_id}`;

    const acceptButton = document.createElement('button');
    acceptButton.textContent = 'Accept';
    acceptButton.onclick = () => {
        updateFriendRequest(data.sender_id, 'accepted');
        requestItem.remove();
    };

    const rejectButton = document.createElement('button');
    rejectButton.textContent = 'Reject';
    rejectButton.onclick = () => {
        updateFriendRequest(data.sender_id, 'refused');
        requestItem.remove();
    };

    requestItem.appendChild(requestText);
    requestItem.appendChild(acceptButton);
    requestItem.appendChild(rejectButton);

    friendRequestList.appendChild(requestItem);
    fetchFriendRequests(); // Fetch and display friend requests
}

function fetchFriendRequests() {
    const accessToken = sessionStorage.getItem('accessToken');
    fetch('http://127.0.0.1:8004/user/friends/listrequests/', {
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
            const friendRequestList = document.getElementById('friend-request-list');
            friendRequestList.innerHTML = '';
            data.pending_requests.forEach(request => {
                const requestItem = document.createElement('li');
                requestItem.classList.add('friend-request');

                const requestText = document.createElement('span');
                requestText.textContent = `Friend request from User ID: ${request}`;

                const acceptButton = document.createElement('button');
                acceptButton.textContent = 'Accept';
                acceptButton.onclick = () => {
                    updateFriendRequest(request, 'accepted');
                    requestItem.remove();
                };

                const rejectButton = document.createElement('button');
                rejectButton.textContent = 'Reject';
                rejectButton.onclick = () => {
                    updateFriendRequest(request, 'refused');
                    requestItem.remove();
                };

                requestItem.appendChild(requestText);
                requestItem.appendChild(acceptButton);
                requestItem.appendChild(rejectButton);

                friendRequestList.appendChild(requestItem);
            });
        })
        .catch(error => console.error('Error fetching friend requests:', error));
}

function updateFriendRequest(friendId, status) {
    const accessToken = sessionStorage.getItem('accessToken');
    fetch('http://127.0.0.1:8004/user/friends/update/', {
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

function displayInviteCode(data) {
    console.log('Invite code received:', data);
    alert(`Invite Code: ${data.invite_code}`);
}

function showMainMenu() {
    document.getElementById('login-signup').classList.remove('active');
    document.getElementById('main-menu').classList.add('active');
    document.getElementById('logged-in-user').textContent = `Logged in as: ${sessionStorage.getItem('username')}`;
    initThreeJS();
    fetchFriendList(); // Fetch and display the friend list
    fetchFriendRequests(); // Fetch and display the friend requests
}

function fetchFriendList() {
    const accessToken = sessionStorage.getItem('accessToken');
    fetch('http://127.0.0.1:8004/user/friends/', {
        headers: {
            'Authorization': `Bearer ${accessToken}`
        }
    })
        .then(response => response.json())
        .then(data => {
            const friendIds = data.friends;
            if (friendIds.length > 0) {
                fetch('http://127.0.0.1:8000/api/auth/users/info/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${accessToken}`
                    },
                    body: JSON.stringify({ user_ids: friendIds })
                })
                    .then(response => response.json())
                    .then(userData => {
                        const friendList = document.getElementById('friend-request-list');
                        friendList.innerHTML = '';
                        friendIds.forEach(friendId => {
                            const li = document.createElement('li');
                            li.textContent = `Friend: ${userData[friendId].username} (ID: ${friendId})`;

                            const removeButton = document.createElement('button');
                            removeButton.textContent = 'Remove Friend';
                            removeButton.onclick = () => {
                                updateFriendRequest(friendId, 'refused');
                                li.remove();
                            };

                            li.appendChild(removeButton);
                            friendList.appendChild(li);
                        });
                    })
                    .catch(error => console.error('Error fetching friend details:', error));
            }
        })
        .catch(error => console.error('Error fetching friend list:', error));
}

function fetchConnectedUsers(accessToken) {
    fetch('http://127.0.0.1:8000/api/user/connected/', {
        headers: {
            'Authorization': `Bearer ${accessToken}`
        }
    })
        .then(response => response.json())
        .then(data => {
            const userList = document.getElementById('user-list');
            userList.innerHTML = '';
            data.users.forEach(user => {
                const li = document.createElement('li');
                li.classList.add('user-item');

                const userInfo = document.createElement('span');
                userInfo.textContent = `${user.username} (ID: ${user.id})`;

                const userActions = document.createElement('div');
                userActions.classList.add('user-actions');

                const inviteButton = document.createElement('button');
                inviteButton.textContent = 'Invite';
                inviteButton.onclick = function () {
                    sendInvite(user.id, globalSocket);
                };

                const friendRequestButton = document.createElement('button');
                friendRequestButton.textContent = 'Send Friend Request';
                friendRequestButton.onclick = function () {
                    sendFriendRequest(user.id);
                };

                userActions.appendChild(inviteButton);
                userActions.appendChild(friendRequestButton);

                li.appendChild(userInfo);
                li.appendChild(userActions);
                userList.appendChild(li);
            });
        })
        .catch(error => console.error('Error fetching connected users:', error));
}

document.getElementById('search-user-form').addEventListener('submit', async function (event) {
    event.preventDefault();
    const username = document.getElementById('search-username').value;
    const accessToken = sessionStorage.getItem('accessToken');
    try {
        const response = await fetch(`http://127.0.0.1:8000/api/auth/search_user/?username=${username}`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        const data = await response.json();
        const searchResults = document.getElementById('search-results');
        searchResults.innerHTML = '';
        if (data.id) {
            searchResults.innerHTML = `<p>${data.username} (ID: ${data.id})</p>`;
        } else {
            searchResults.innerHTML = `<p>${data.error}</p>`;
        }
    } catch (error) {
        console.error('Error searching user:', error);
        alert('Search failed. Please try again.');
    }
});

document.getElementById('search-username').addEventListener('input', async function () {
    const username = document.getElementById('search-username').value;
    const accessToken = sessionStorage.getItem('accessToken');
    if (username.length < 1) { // Require at least 1 character
        document.getElementById('search-results').innerHTML = '';
        return;
    }
    try {
        const response = await fetch(`http://127.0.0.1:8000/api/auth/search_user/?username=${username}`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        const data = await response.json();
        const searchResults = document.getElementById('search-results');
        searchResults.innerHTML = '';
        if (data.users && data.users.length > 0) {
            searchResults.innerHTML = '<ul>' + data.users.map(user => `
                <li>
                    ${user.username} (ID: ${user.id})
                    <button onclick="sendFriendRequest(${user.id})">Send Friend Request</button>
                </li>`).join('') + '</ul>';
        } else if (data.error) {
            searchResults.innerHTML = `<p>${data.error}</p>`;
        } else {
            searchResults.innerHTML = '<p>No users found</p>';
        }
    } catch (error) {
        console.error('Error searching user:', error);
        alert('Search failed. Please try again.');
    }
});