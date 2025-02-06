function settingsNav() {
	const accessToken = sessionStorage.getItem('accessToken');
	if (!accessToken) {
		console.error('Access token not found');
		// return;
	}
	const userId = sessionStorage.getItem('userId');

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
		// console.log(user.id);
		document.getElementById('profile-username').innerText = user.username;
		document.getElementById('profile-id').innerText = user.id;
		document.getElementById('username').innerText = user.username;
		document.getElementById('userMail').innerText = user.email;
		fetchProfileImages(user.id, accessToken, ['userIcon']);
	})
	.catch(error => console.error('Error viewing profile:', error));
};

settingsNav();

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
				const imgElement = document.getElementById(imageElementIds[index]);
				imgElement.src = image.image_url;
				imgElement.alt = `Image ${image.id}`;
				imgElement.type = image.content_type;
				
			}
		});
	})
	.catch(error => console.error('Error fetching profile images:', error));
}

document.getElementById('upload-image-form').addEventListener('submit', async function (event) {
	event.preventDefault();
	const accessToken = sessionStorage.getItem('accessToken');
	const userId = sessionStorage.getItem('userId');
	const fileInput = document.getElementById('upload-image');
	const formData = new FormData();
	formData.append('image', fileInput.files[0]);

	try {
		const response = await fetch('https://localhost:8443/media/upload/', {
			method: 'POST',
			headers: {
				'Authorization': 'Bearer ' + accessToken
			},
			body: formData
		});
		if (response.ok) {
			alert('Image uploaded successfully.');
			fetchProfileImages(userId, accessToken, 'settings-profile-image');
		} else {
			alert('Failed to upload image. Please try again.');
		}
	} catch (error) {
		console.error('Error uploading image:', error);
		alert('Failed to upload image. Please try again.');
	}
});

document.addEventListener('DOMContentLoaded', function () {
    console.log('DOM fully loaded and parsed');
});

document.getElementById('editBtnUsername').addEventListener('click', function () {
    console.log('edit button clicked');
    toggleEditForm('username');
});
document.getElementById('saveBtnUsername').addEventListener('click', function () {
    saveField('username');
});
document.getElementById('cancelBtnUsername').addEventListener('click', function () {
    toggleEditForm('username');
});

document.getElementById('editBtnUserpwrd').addEventListener('click', function () {
    toggleEditForm('userpwrd');
});
document.getElementById('saveBtnUserpwrd').addEventListener('click', function () {
    saveField('userpwrd');
});
document.getElementById('cancelBtnUserpwrd').addEventListener('click', function () {
    toggleEditForm('userpwrd');
});

document.getElementById('editBtnUserMail').addEventListener('click', function () {
    toggleEditForm('userMail');
});
document.getElementById('saveBtnUserMail').addEventListener('click', function () {
    saveField('userMail');
});
document.getElementById('cancelBtnUserMail').addEventListener('click', function () {
    toggleEditForm('userMail');
});


function toggleEditForm(fieldId) {
    const form = document.getElementById(`${fieldId}-form`);
    const span = document.getElementById(fieldId);
    if (fieldId ==! 'userpwrd') {
		const input = document.getElementById(`${fieldId}-input`);
	}
		const button = document.getElementById(`editBtn${capitalizeFirstLetter(fieldId)}`);
    const saveButton = document.getElementById(`saveBtn${capitalizeFirstLetter(fieldId)}`);

	// console.log(`BEFORE:: form : ${form.style.display} span : ${span.style.display} input : ${input.style.display} button : ${button.style.display} saveButton : ${saveButton.style.display}`);
    if (form.style.display === 'none') {
        if (fieldId ==! 'userpwrd') {
			input.placeholder = span.innerText;
		}
        form.style.display = 'block';
        span.style.display = 'none';
        button.style.display = 'none';
        // saveButton.style.display = 'inline';
    } else {
        form.style.display = 'none';
        span.style.display = 'inline';
        button.style.display = 'inline';
        // saveButton.style.display = 'none';
    }
	// console.log(`AFTER:: form : ${form.style.display} span : ${span.style.display} input : ${input.style.display} button : ${button.style.display} saveButton : ${saveButton.style.display}`);
    
}

function saveField(fieldId) {
	alert(`saveField(${fieldId})`);
    // const input = document.getElementById(`${fieldId}-input`);
    // const newValue = input.value;
    // const span = document.getElementById(fieldId);
    // span.innerText = newValue;
    if (fieldId === 'userMail' || fieldId === 'username') {
		updateUsernameOrEmail();
    } else {
		updatePassword();
	}
    toggleEditForm(fieldId);
    // Add code here to save the new value to the server if needed
}

function updatePassword() {
	console.log('updatePassword()');
    const oldPassword = document.getElementById('old-userpwrd-input').value;
    const newPassword = document.getElementById('new-userpwrd-input').value;
    const accessToken = sessionStorage.getItem('accessToken');

    console.log('Preparing to send request to update password');
    console.log('old_password:', oldPassword);
    console.log('new_password:', newPassword);

    fetch('https://localhost:8443/auth/password/update/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + accessToken
        },
        body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
    })
    .then(response => response.json().then(data => ({ status: response.status, body: data })))
    .then(({ status, body }) => {
        if (status === 200) {
            alert('Password updated successfully');
        } else {
            alert('Failed to update password: ' + body.message);
        }
    })
    .catch(error => {
        console.error('Error updating password:', error);
        alert('An error occurred while updating the password');
    });
}

function updateUsernameOrEmail() {
	const accessToken = sessionStorage.getItem('accessToken');
	const currentUsername = document.getElementById('username').innerText;
	const currentEmail = document.getElementById('userMail').innerText;
	const newUsername = document.getElementById('username-input').value || currentUsername;
	const newEmail = document.getElementById('userMail-input').value || currentEmail;
	console.log('Preparing to send request to update user details');
	console.log('Access Token:', accessToken);
	console.log('Current Username:', currentUsername);
	console.log('Current Email:', currentEmail);
	console.log('New Username:', newUsername);
	console.log('New Email:', newEmail);
	fetch('https://localhost:8443/auth/update/', {
		method: 'PUT',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + accessToken
		},
		body: JSON.stringify({ username: newUsername, email: newEmail })
	})
	.then(response => response.json().then(data => ({ status: response.status, body: data })))
	.then(({ status, body }) => {
		if (status === 200) {
			sessionStorage.setItem('username', body.username);
			document.getElementById('profile-username').innerText = body.username;
			document.getElementById('username').innerText = body.username;
			document.getElementById('userMail').innerText = body.email;
			alert('Changes saved successfully.');
		} else {
			alert('Failed to save changes. Please try again.');
		}
	})
	.catch(error => {
		console.error('Error saving changes:', error);
		alert('Failed to save changes. Please try again.');
	});
}

function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}