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
		fetchProfileImages(user.id, accessToken, ['userIcon']);
		fetchUserMatches(user.id, accessToken);
		fetchUserStatistics(user.id, accessToken);
		fetchUserFriends(user.id, accessToken);
	})
	.catch(error => console.error('Error viewing profile:', error));
};

profileNav();



function fetchProfileImages(userIds, accessToken, imageElementIds) {
	const cacheBuster = new Date().getTime(); // Generate a unique timestamp
	fetch(`https://localhost:8443/media/profile-images/?cb=${cacheBuster}`, {
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
				const imgElement = document.getElementById(imageElementIds);
				imgElement.src = image.image_url;
				imgElement.alt = `Image ${image.id}`;
				imgElement.type = image.content_type;
				
			}
		});
	})
	.catch(error => console.error('Error fetching profile images:', error));
}

function fetchUserMatches(userId, accessToken) {
	fetch(`https://127.0.0.1:8443/user/${userId}/matches/`, {
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
		const matchesList = document.getElementById('history');
		matchesList.innerHTML = '';
		data.matches.forEach(match => {
			const matchElement = document.createElement('tr');
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

function fetchUserStatistics(userId, accessToken) {
    // Fetch and display user statistics
}

function fetchUserFriends(userId, accessToken) {
    // Fetch and display user friends
}