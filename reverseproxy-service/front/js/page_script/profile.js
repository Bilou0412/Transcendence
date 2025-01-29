function profileNav() {
	const accessToken = sessionStorage.getItem('accessToken');
	if (!accessToken) {
		console.error('Access token not found');
		// return;
	}
	const userId = sessionStorage.getItem('userId');
	const username = sessionStorage.getItem('username');
	const email = sessionStorage.getItem('email');

	// document.getElementById('profile-username').innerText = username;
	// document.getElementById('profile-id').innerText = userId;
	// document.getElementById('profile-email').innerText = `Email: ${email}`;
	// document.getElementById('userID').innerText = username;
	

	fetch('https://localhost:8443/auth/users/info/', {
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
		document.getElementById('profile-username').innerText = user.username;
		document.getElementById('profile-id').innerText = user.id;
		// document.getElementById('profile-email').innerText = `Email: ${user.email}`;
		fetchProfileImages(user.id, accessToken, ['profile-image']);
		fetchUserMatches(user.id, accessToken);
		fetchUserStatistics(user.id, accessToken);
		fetchUserFriends(user.id, accessToken);
	})
	.catch(error => console.error('Error viewing profile:', error));
};

profileNav();


function fetchProfileImages(userId, accessToken, imageElementIds) {
    // Fetch and display profile images
}

function fetchUserMatches(userId, accessToken) {
    // Fetch and display user match history
}

function fetchUserStatistics(userId, accessToken) {
    // Fetch and display user statistics
}

function fetchUserFriends(userId, accessToken) {
    // Fetch and display user friends
}