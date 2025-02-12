import { fetchProfileImages } from './utils.js';
import { buildFriendList } from './friendList.js';

console.log('chat.js loaded');

let chatSocket = null;

const accessToken = sessionStorage.getItem('accessToken');
const userId = sessionStorage.getItem('userId');
fetchProfileImages([userId], accessToken, ['self-avatar']);

function loadChatPage() {
	const accessToken = sessionStorage.getItem('accessToken');
	if (!accessToken) {
		console.error('Access token not found');
		return;
	}
    console.log('Loading chat page');
	buildFriendList(accessToken, 'friendList', Chat);
}
loadChatPage();

function formatTime(dateStr) {
    const date = new Date(dateStr);

    date.setHours(date.getUTCHours() + 1);

    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');

    return `${hours}:${minutes}`;
}

function Chat(userIdToChat) {
	const accessToken = sessionStorage.getItem('accessToken');
	if (userIdToChat && accessToken) {
		if (chatSocket) {
			chatSocket.close();
		}
		chatSocket = new WebSocket(`wss://${window.location.host}/chat/${userIdToChat}/`, ['Bearer_' + accessToken]);

		chatSocket.onopen = () => {
			document.getElementById('chat-history-body').innerHTML = '';
			document.getElementById('other-avatar').onclick = () => {
				viewProfile(userIdToChat);
			}
			fetchProfileImages([userIdToChat], accessToken, ['other-avatar']);
			console.log('Direct Message WebSocket connection opened');
		};

		chatSocket.onmessage = event => {
			const message = JSON.parse(event.data);
			console.log('Received message:', message);
			const chatMessagesContainer = document.getElementById('chat-history-body');
			// chatMessagesContainer.innerHTML = '';

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

document.getElementById('send-message').addEventListener('click', function () {
    console.log('send button clicked');
    sendChatMessage();
});

function sendChatMessage() {
	const messageInput = document.getElementById('message-input');
	const message = messageInput.value.trim();
	console.log('Sending message:', message);
	if (!message) {
		alert('Please enter a message to send.');
		return;
	}
	if (chatSocket) {
		console.log('really Sending message:', message);
		chatSocket.send(JSON.stringify({ message }));
		messageInput.value = '';
	}
}