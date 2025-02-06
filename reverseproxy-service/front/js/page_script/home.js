function displayInviteCode(data) {
    console.log('Invite code received:', data);
    alert(`Invite Code: ${data.invite_code}`);
}

function connectWebSocket(accessToken, username, userId) {
    console.log('Connecting to WebSocket...');
    const userList = document.getElementById('user-list');
    const friendRequestList = document.getElementById('friend-request-list');
    console.log(accessToken);
    console.log(userId);
    console.log(username);

    const socket = new WebSocket(`wss://localhost:8443/wsmanagement/lobby/`, [`Bearer_${accessToken}`]);
    globalSocket = socket;
    socket.onmessage = function (event) {
        const data = JSON.parse(event.data);
        console.log('Received WebSocket message:', data);

        switch (data.type) {
            case 'invite_code':
                displayInviteCode(data);
                break;
            case 'friend_request':
                handleFriendRequest(data, friendRequestList);
                break;
            default:
                console.log('Unhandled message type:', data.type);
        }
    }
};



const accessToken = sessionStorage.getItem('accessToken');
const username = sessionStorage.getItem('username');
const userId = sessionStorage.getItem('userId');
connectWebSocket(accessToken, username, userId);