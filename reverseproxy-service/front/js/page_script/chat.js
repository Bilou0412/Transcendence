import { fetchProfileImages, fetchUsersInfos } from './fetchData.js';
import { buildFriendList } from './friendList.js';

const accessToken = sessionStorage.getItem('accessToken');
const userId = sessionStorage.getItem('userId');

fetchProfileImages([userId], accessToken, ['self-avatar']);

function loadChatPage() {
	if (!accessToken) {
		console.error('Access token not found');
		return;
	}
    console.log('Loading chat page');
	buildFriendList(accessToken, 'friendList', Chat);
}

if (window.location.pathname === '/chat') {
	
	loadChatPage();

	document.getElementById('send-message').addEventListener('click', function () {
		sendChatMessage();
	});
}

function formatTime(dateStr) {
    const date = new Date(dateStr);

    date.setHours(date.getUTCHours() + 1);

    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');

    return `${hours}:${minutes}`;
}

function Chat(userIdToChat) {
    if (!userIdToChat && !accessToken)
        return;
    if (window.chatSocket && window.chatSocket.readyState === WebSocket.OPEN) {
        console.log('Closing existing Chat WebSocket connection...');
        window.chatSocket.close();
    }
    console.log('Opening new Chat WebSocket connection...');
    const encodedToken = encodeURIComponent(accessToken);
    window.chatSocket = new WebSocket(`wss://${window.location.host}/ws/chat/${userIdToChat}/?${encodedToken}`);

    window.chatSocket.onopen = () => {
        document.getElementById('chat-history-body').innerHTML = '';
        fetchProfileImages([userIdToChat], accessToken, ['other-avatar']);
        console.log('Direct Message WebSocket connection opened');
        //change title of chat page
        let chat_with = document.getElementById('chat-with');
        fetchUsersInfos(accessToken, [userIdToChat])
        .then (userData => {
            console.log(userData);
            chat_with.textContent = userData[userIdToChat].username;
        });
    };

    window.chatSocket.onmessage = event => {
        const message = JSON.parse(event.data);
        const chatMessagesContainer = document.getElementById('chat-history-body');
        if (message.type === 'message_history') {
            message.messages.forEach(msg => {
                const messageElement = document.createElement('div');
                messageElement.classList.add('message');
                messageElement.textContent = `[${formatTime(msg.timestamp)}]  ${msg.sender}: ${msg.content}`;
                chatMessagesContainer.appendChild(messageElement);
                chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
            });
        } else if (message.type === 'chat_message') {
            const messageElement = document.createElement('div');
            messageElement.classList.add('message');
            messageElement.textContent = `[${formatTime(message.timestamp)}]  ${message.sender}: ${message.message}`;
            chatMessagesContainer.appendChild(messageElement);
            chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
        }
    };

    window.chatSocket.onclose = () => {
        console.log('Chat WebSocket connection closed');
    };
}

function sendChatMessage() {
	const messageInput = document.getElementById('message-input');
	const message = messageInput.value.trim();

	if (message && window.chatSocket) {
		window.chatSocket.send(JSON.stringify({ message }));
		messageInput.value = '';
	}
}

export function quit() {
    if (window.chatSocket) {
        console.log('Closing Chat WebSocket connection due to page change...');
        window.chatSocket.close();
        window.chatSocket = null;
    }
}