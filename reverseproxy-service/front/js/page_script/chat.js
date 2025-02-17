import { fetchProfileImages } from './fetchData.js';
import { buildFriendList } from './friendList.js';

const accessToken = sessionStorage.getItem('accessToken');
const userId = sessionStorage.getItem('userId');
let chatSocket = null;

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
	if (userIdToChat && accessToken) {
		if (chatSocket && chatSocket.readyState === WebSocket.OPEN) {
			console.log('Closing existing Chat WebSocket connection...');
			chatSocket.close();
		}
		console.log('Opening new Chat WebSocket connection...');
		const encodedToken = encodeURIComponent(accessToken);
		chatSocket = new WebSocket(`wss://${window.location.host}/chat/${userIdToChat}/?${encodedToken}`);

		chatSocket.onopen = () => {
			document.getElementById('chat-history-body').innerHTML = '';
			fetchProfileImages([userIdToChat], accessToken, ['other-avatar']);
			console.log('Direct Message WebSocket connection opened');
		};

		chatSocket.onmessage = event => {
			const message = JSON.parse(event.data);
			const chatMessagesContainer = document.getElementById('chat-history-body');

			if (message.type === 'message_history') {
				message.messages.forEach(msg => {
					const messageElement = document.createElement('div');
					messageElement.classList.add('message');
                    messageElement.textContent = `[${formatTime(msg.timestamp)}]  ${msg.sender}: ${msg.content}`;
                    chatMessagesContainer.appendChild(messageElement);
					chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
				})
			} else if (message.type === 'chat_message') {
				const messageElement = document.createElement('div');
				messageElement.classList.add('message');
				messageElement.textContent = `[${formatTime(message.timestamp)}]  ${message.sender}: ${message.message}`;
				chatMessagesContainer.appendChild(messageElement);
				chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
			}
		}
		chatSocket.onclose = () => {
			console.log('Chat WebSocket connection closed');
		};
	} else {
		alert('Please enter a valid User ID and make sure you are logged in.');
	}
}

function sendChatMessage() {
	const messageInput = document.getElementById('message-input');
	const message = messageInput.value.trim();
	if (!message)
		return;
	if (chatSocket) {
		chatSocket.send(JSON.stringify({ message }));
		messageInput.value = '';
	}
}

// Add cleanup function
export function quit() {
    if (chatSocket) {
        console.log('Closing Chat WebSocket connection due to page change...');
        chatSocket.close();
        chatSocket = null;
    }
}