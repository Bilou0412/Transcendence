export function fetchProfileImages(userIds, accessToken, imageElementIds) {
	const cacheBuster = new Date().getTime(); // Generate a unique timestamp
	fetch(`https://${window.location.host}/media/profile-images/?cb=${cacheBuster}`, {
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
				const imgElement = document.getElementById(imageElementIds[index]);
				imgElement.src = image.image_url;
				imgElement.alt = `Image ${image.id}`;
				imgElement.type = image.content_type;
				
			}
		});
	})
	.catch(error => console.error('Error fetching profile images:', error));
}

export function fetchUsersInfos(accessToken, friendIds) {
	return fetch(`https://${window.location.host}/auth/users/info/`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${accessToken}`
		},
		body: JSON.stringify({ user_ids: friendIds })
	})
	.then(response => response.json())
	.then(userData => {
		return userData;
	})
}

export function fetchFriendList(accessToken) {
	return fetch(`https://${window.location.host}/usermanagement/friends/`, {
		headers: {
			'Authorization': `Bearer ${accessToken}`
		}
	})
	.then(response => response.json())
	.then(data => {
		return data.friends;
	})

	.catch(error => console.error('Error fetching friend list:', error));
}