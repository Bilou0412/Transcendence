import { fetchProfileImages } from './fetchData.js';
import { buildFriendList } from './friendList.js';


export function profileNav(idToSearch) {
	const accessToken = sessionStorage.getItem('accessToken');
	if (!accessToken) {
		console.error('Access token not found');
		return;
	}

	fetch(`https://${window.location.host}/auth/users/info/`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + accessToken
		},
		body: JSON.stringify({ user_ids: [idToSearch] })
	})
	.then(response => response.json())
	.then(data => {
		const user = data[idToSearch];
		if (!document.getElementById('profile-username'))
			return;
		document.getElementById('profile-username').innerText = user.username;
		document.getElementById('profile-id').innerText = user.id;
		fetchProfileImages(user.id, accessToken, ['userIcon']);
		fetchUserMatches(user.id, accessToken);
		fetchFriendRequests();
		buildFriendList(accessToken, 'friendList-body', profileNav);
		if (user['Student']) {
			document.getElementById('editBtn').style.display = 'none';
		}
		if (sessionStorage.getItem('userId') !== String(idToSearch)) {
			document.getElementById('editBtn').style.display = 'none';
		}

		if (document.getElementById('search_bar')) {
			document.getElementById('search_bar').addEventListener('input', function(event) {
				const query = event.target.value;
				fetchSearchResults(query);
			});
		}

	})
	.catch(error => console.error('Error viewing profile:', error));
}


export function viewProfile(friendId) {
    // Clean up existing friend list before navigation
    document.querySelectorAll('.friend-item').forEach(element => element.remove());
    
    // Navigate to profile
    route(null, '/profile');
    
    // Wait for navigation to complete before initializing profile
    setTimeout(() => {
        profileNav(friendId);
    }, 100);
}


if (window.location.pathname === '/profile') {
	
	if (sessionStorage.getItem('userId')) {
		profileNav(sessionStorage.getItem('userId'));
	}
}

function fetchSearchResults(query) {
	if (query.length > 0) {
		fetch(`https://${window.location.host}/auth/search_user/?username=${query}`, {
			method: 'GET',
			headers: {
				'Content-Type': 'application/json',
				'Authorization': 'Bearer ' + sessionStorage.getItem('accessToken')
			}
		})
		.then(response => response.json())
		.then(data => {
			if (data.users) {
				console.log('Search results:', data.users);
				displaySearchResults(data.users);
			} else {
				console.error('No users found');
			}
		})
		.catch(error => console.error('Error searching users:', error));
	} else {
		clearSearchResults();
	}
}

function displaySearchResults(users) {
	const resultsContainer = document.getElementById('searchResults-body');
	const userElements = document.querySelectorAll('[id^="user-"]');
    const friendIds = new Set(Array.from(userElements).map(element => element.id.replace('user-', '')));

	resultsContainer.innerHTML = '';
	users.forEach(user => {
		const userElement = document.createElement('div');
		userElement.className = 'friend-item';
		
		const avatar = document.createElement('img');
		// avatar.src = '../css/icon/rounded_login.png'; // Placeholder avatar
		// avatar.alt = 'User Avatar';
		avatar.className = 'friend-avatar';
		avatar.id = `search-avatar-${user.id}`;
		avatar.onclick = function () {
            profileNav(user.id);
        };
		
		const userInfo = document.createElement('div');
		userInfo.className = 'friend-info';
		const userName = document.createElement('div');
		userName.className = 'friend-name';
		userName.innerText = `${user.username} (#${user.id})`;
		userName.onclick = function () {
            profileNav(user.id);
        };
		userInfo.appendChild(userName);
		
		const userActions = document.createElement('div');
		userActions.className = 'friend-actions';
		if (String(user.id) !== sessionStorage.getItem('userId') && !friendIds.has(String(user.id))) {
			const friendRequestButton = document.createElement('button');
			friendRequestButton.className = 'btn btn-friend-request';
			friendRequestButton.innerText = 'Send Friend Request';
			friendRequestButton.onclick = function () {
				sendFriendRequest(user.id);
			};
			userActions.appendChild(friendRequestButton);
		}
		
		userElement.appendChild(avatar);
		userElement.appendChild(userInfo);
		userElement.appendChild(userActions);
		
		resultsContainer.appendChild(userElement);
	});
	fetchProfileImages(users.map(user => user.id), sessionStorage.getItem('accessToken'), users.map(user => `search-avatar-${user.id}`));
}

function clearSearchResults() {
	const resultsContainer = document.getElementById('searchResults-body');
	resultsContainer.innerHTML = '';
}

function calculateTimeDifference(date1Str, date2Str) {
    const date1 = new Date(date1Str);
    const date2 = new Date(date2Str);

    const diffMs = Math.abs(date2 - date1);
    const diffSeconds = Math.floor(diffMs / 1000);
    const diffMinutes = Math.floor(diffSeconds / 60);
    const remainingSeconds = diffSeconds % 60;

    return `${diffMinutes}min${remainingSeconds}s`;
}

function formatDate(dateStr) {
    const date = new Date(dateStr);
    
    const day = String(date.getUTCDate()).padStart(2, '0');
    const month = String(date.getUTCMonth() + 1).padStart(2, '0'); // Months are 0-based
    const year = date.getUTCFullYear();
    const hours = String(date.getUTCHours()).padStart(2, '0');
    const minutes = String(date.getUTCMinutes()).padStart(2, '0');

    return `${day}/${month}/${year} ${hours}:${minutes}`;
}


function fetchUserMatches(userId, accessToken) {
	console.log('Fetching user matches...');
	fetch(`https://${window.location.host}/usermanagement/${userId}/matches/`, {
		method: 'GET',
		headers: {
			'Authorization': 'Bearer ' + accessToken
		}
	})
	.then(response => response.json())
	.then(data => {
		if (!data || !data.matches) {
			const historyTable = document.getElementById('history');
			while (historyTable.rows.length > 1) {
				historyTable.deleteRow(1);
			}
			const newRow = historyTable.insertRow();
			newRow.className = 'match';
			newRow.innerHTML = `
				<td colspan="7">No matches found</td>
			`;
			return;
		}

		const historyTable = document.getElementById('history');
		
		while (historyTable.rows.length > 1) {
			historyTable.deleteRow(1);
		}

		// Stats variables
		let totalGames = 0;
		let wins = 0;
		let totalPointsScored = 0;
		let totalPointsTaken = 0;
		let totalTimePlayedSeconds = 0;

		data.matches.forEach(match => {
			totalGames++;

			const isPlayer1 = match.player_1_id == userId;
			const playerScore = isPlayer1 ? match.score_player_1 : match.score_player_2;
			const opponentScore = isPlayer1 ? match.score_player_2 : match.score_player_1;

			totalPointsScored += playerScore;
			totalPointsTaken += opponentScore;

			if (playerScore > opponentScore) {
				wins++;
			}

			// Convert match time difference into total seconds played
			const timePlayedStr = calculateTimeDifference(match.end_time, match.start_time);
			const matchTimeSeconds = parseTimeToSeconds(timePlayedStr);
			totalTimePlayedSeconds += matchTimeSeconds;

			const newRow = historyTable.insertRow();
			newRow.className = 'match';
			newRow.innerHTML = `
				<td>${match.match_id}</td>
				<td>${match.player_1_id}</td>
				<td>${match.player_2_id}</td>
				<td>${match.score_player_1}</td>
				<td>${match.score_player_2}</td>
				<td>${timePlayedStr}</td>
				<td>${formatDate(match.start_time)}</td>
			`;
		});

		// Compute stats
		const winRate = totalGames > 0 ? (wins / totalGames) * 100 : 0;
		const kdRatio = totalPointsTaken > 0 ? (totalPointsScored / totalPointsTaken) : totalPointsScored;
		const avgPointsPerGame = totalGames > 0 ? totalPointsScored / totalGames : 0;
		const avgPointsTakenPerGame = totalGames > 0 ? totalPointsTaken / totalGames : 0;
		const formattedTotalTime = formatTime(totalTimePlayedSeconds);

		// Update stats in HTML
		updateStats(
			totalGames, 
			winRate.toFixed(2) + '%', 
			kdRatio.toFixed(2), 
			formattedTotalTime, 
			avgPointsPerGame.toFixed(2), 
			avgPointsTakenPerGame.toFixed(2), 
			totalPointsScored, 
			totalPointsTaken
		);
	})
	.catch(error => console.error('Error fetching user matches:', error));
}

function parseTimeToSeconds(timeStr) {
	const match = timeStr.match(/(\d+)min(\d+)s/);
	if (match) {
		const minutes = parseInt(match[1], 10);
		const seconds = parseInt(match[2], 10);
		return minutes * 60 + seconds;
	}
	return 0;
}

// Convert total seconds into "Xmin Ys" format
function formatTime(seconds) {
	const minutes = Math.floor(seconds / 60);
	const remainingSeconds = seconds % 60;
	return `${minutes}min${remainingSeconds}s`;
}

function updateStats(games, winRate, kd, timePlayed, pointsPerGame, pointsTakenPerGame, totalScored, totalTaken) {
    // updateWinrateCircle(winRate);
    
	document.getElementById('games-played').textContent = games;
    // document.getElementById('winrate').textContent = winRate;
    document.getElementById('kd').textContent = kd;
    document.getElementById('time-played').textContent = timePlayed;
    document.getElementById('points-per-game').textContent = pointsPerGame;
    document.getElementById('points-taken-per-game').textContent = pointsTakenPerGame;
    document.getElementById('total-points-scored').textContent = totalScored;
    document.getElementById('total-points-taken').textContent = totalTaken;

    // Convert winRate from "XX%" format to a number
    const winRateValue = parseFloat(winRate);

    // // Render the winrate chart
    updateWinrateCircle(winRateValue);
}

function updateWinrateCircle(winRateValue) {
    const circle = document.getElementById('winrate-progress');
    const text = document.getElementById('winrate-text');

    // Stroke-dasharray is 2πr (full circle length)
    const circleLength = 2 * Math.PI * 45; 
    const progress = circleLength * (1 - winRateValue / 100);

    circle.style.strokeDashoffset = progress;
    text.textContent = winRateValue.toFixed(1) + '%';
}

export function fetchFriendRequests() {
	const accessToken = sessionStorage.getItem('accessToken');
	fetch(`https://${window.location.host}/usermanagement/friends/listrequests/`, {
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
		if (!data.pending_requests) {
			return;
		}
		const requestContainer = document.getElementById('requestResults-body');
		if (requestContainer)
			requestContainer.innerHTML = '';

		const userIds = data.pending_requests.map(request => request);
		if (userIds.length === 0) {
			console.log('No friend requests found');
			return;
		}
		// Fetch user information
		fetch(`https://${window.location.host}/auth/users/info/`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Authorization': 'Bearer ' + accessToken
			},
			body: JSON.stringify({ user_ids: userIds })
		})
		.then(response => response.json())
		.then(userData => {
			data.pending_requests.forEach(requestId => {
				const user = userData[requestId];
				if (!user) {
					console.error(`User data not found for request ID: ${requestId}`);
					return;
				}
				const requestElement = document.createElement('div');
				requestElement.className = 'friend-item';
				
				const avatar = document.createElement('img');
				avatar.src = '../css/icon/rounded_login.png'; // Placeholder avatar
				avatar.alt = 'User Avatar';
				avatar.id = `request-avatar-${requestId}`;
				avatar.className = 'friend-avatar';
				
				const userInfo = document.createElement('div');
				userInfo.className = 'friend-info';
				const userName = document.createElement('div');
				userName.className = 'friend-name';
				userName.innerText = `Friend request from ${user.username}`;
				userInfo.appendChild(userName);
				
				const userActions = document.createElement('div');
				userActions.className = 'friend-actions';
				const acceptButton = document.createElement('button');
				acceptButton.className = 'btn btn-accept-request';
				acceptButton.innerText = 'Accept';
				acceptButton.onclick = function () {
					respondToFriendRequest(requestId, true);
					requestElement.remove();
				};
				const rejectButton = document.createElement('button');
				rejectButton.className = 'btn btn-reject-request';
				rejectButton.innerText = 'Reject';
				rejectButton.onclick = function () {
					respondToFriendRequest(requestId, false);
					requestElement.remove();
				};
				userActions.appendChild(acceptButton);
				userActions.appendChild(rejectButton);
				
				requestElement.appendChild(avatar);
				requestElement.appendChild(userInfo);
				requestElement.appendChild(userActions);
				
				requestContainer.appendChild(requestElement);
			});
			fetchProfileImages(userIds, accessToken, userIds.map(id => `request-avatar-${id}`));
		})
		.catch(error => console.error('Error fetching user information:', error));
	})
	.catch(error => console.error('Error fetching friend requests:', error));
}

function respondToFriendRequest(friendId, accept) {
	const accessToken = sessionStorage.getItem('accessToken');
	fetch(`https://${window.location.host}/usermanagement/friends/update/`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${accessToken}`
		},
		body: JSON.stringify({
			friend_id: friendId,
			status: accept ? 'accepted' : 'refused'
		})
	})
	.then(response => response.json())
	.then(data => {
		console.log(`Friend request ${accept ? 'accepted' : 'refused'}:`, data);
		fetchFriendRequests(); // Refresh friend requests
		buildFriendList(accessToken, "friendList-body",profileNav);
		alert(`Friend request ${accept ? 'accepted' : 'refused'} successfully!`);
	})
	.catch(error => {
		console.error(`Error responding to friend request:`, error);
		alert(`Failed to respond to friend request`);
	});
}

function sendFriendRequest(receiverId) {
	const accessToken = sessionStorage.getItem('accessToken');
	fetch(`https://${window.location.host}/usermanagement/friends/request/`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${accessToken}`
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
