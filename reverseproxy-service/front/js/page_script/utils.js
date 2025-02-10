export function fetchProfileImages(userIds, accessToken, imageElementIds) {
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
				const imgElement = document.getElementById(imageElementIds[index]);
				imgElement.src = image.image_url;
				imgElement.alt = `Image ${image.id}`;
				imgElement.type = image.content_type;
				
			}
		});
	})
	.catch(error => console.error('Error fetching profile images:', error));
}