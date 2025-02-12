// export let globalSocket = null;

export async function connectWebSocket(accessToken, username, userId, globalSocket) {
    console.log('Connecting to WebSocket...');
    const userList = document.getElementById('user-list');
    const friendRequestList = document.getElementById('friend-request-list');
    console.log(accessToken);
    console.log(userId);
    console.log(username);

    const socket = new WebSocket(`wss://${window.location.host}/wsmanagement/lobby/`, [`Bearer_${accessToken}`]);
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


function displayInviteCode(data) {
    console.log('Invite code received:', data);
    alert(`Invite Code: ${data.invite_code}`);
}

const accessToken = sessionStorage.getItem('accessToken');
const username = sessionStorage.getItem('username');
const userId = sessionStorage.getItem('userId');
if (accessToken && username && userId)
    connectWebSocket(accessToken, username, userId);