import { initializeGame } from "../pong/main.js";
import { sleep } from "../pong/resetBall.js";

// import { initializeGame } from "../pong/main";

// export let globalSocket = null;
export let socket = null;

export async function connectWebSocket(accessToken, username, userId, globalSocket) {
    console.log('Connecting to WebSocket...');
    const userList = document.getElementById('user-list');
    const friendRequestList = document.getElementById('friend-request-list');
    console.log(accessToken);
    console.log(userId);
    console.log(username);

    socket = new WebSocket(`wss://${window.location.host}/wsmanagement/lobby/`, [`Bearer_${accessToken}`]);
    globalSocket = socket;
    socket.onmessage = function (event) {
        const data = JSON.parse(event.data);
        console.log('Received WebSocket message:', data);

        switch (data.type) {
            case 'invite_code':
                receivedInviteCode(data);
                break;
            case 'friend_request':
                handleFriendRequest(data, friendRequestList);
                break;
            default:
                console.log('Unhandled message type:', data.type);
        }
    }
};


async function receivedInviteCode(data) {
    const userConfirmed = confirm(`Inviter id: ${data.inviter_id}\nDo you want to enter the game?`);
    if (userConfirmed) {
        // Add the action to be performed if the user clicks "OK"
        console.log('User chose to enter the game');
        route(null, '/pong');
        await sleep(500);
        initializeGame(data.invite_code);
    } else {
        console.log('User chose not to enter the game');
    }
}


export function inviteGame(inviteeId) {
    console.log('Inviting user to game:', inviteeId);
    console.log('i am : ', sessionStorage.getItem('userId'));
    socket.send(JSON.stringify({
        invitee_id: inviteeId
    }));
}

const accessToken = sessionStorage.getItem('accessToken');
const username = sessionStorage.getItem('username');
const userId = sessionStorage.getItem('userId');
if (accessToken && username && userId)
    connectWebSocket(accessToken, username, userId);