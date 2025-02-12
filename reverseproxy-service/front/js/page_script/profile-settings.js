function settingsNav() {
	const accessToken = sessionStorage.getItem('accessToken');
	if (!accessToken) {
		console.error('Access token not found');
		// return;
	}
	const userId = sessionStorage.getItem('userId');

	fetch(`https://${window.location.host}/auth/users/info/`, {
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
		const btn2FA = document.getElementById('btn2FA');
		if (user['2fa']) {
			btn2FA.innerText = 'Disable 2FA';
			btn2FA.addEventListener('click', disable2FA);
		} else {
			btn2FA.addEventListener('click', enable2FA);
		}
		if (user['Student']) {
			document.getElementById('editBtnUsername').style.display = 'none';
			document.getElementById('editBtnUserpwrd').style.display = 'none';
			document.getElementById('editBtnUserMail').style.display = 'none';
			document.getElementById('upload-image-form').style.display = 'none';
		}
	})
	.catch(error => console.error('Error viewing profile:', error));
};

settingsNav();

function fetchProfileImages(userIds, accessToken, imageElementIds) {
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
		const response = await fetch(`https://${window.location.host}/media/upload/`, {
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

async function enable2FA(event) {
	event.preventDefault();
	const accessToken = sessionStorage.getItem('accessToken');
	try {
		const response = await fetch(`https://${window.location.host}/auth/2fa/enable/`, {
			method: 'GET',
			headers: {
				'Authorization': 'Bearer ' + accessToken
			}
		});
		if (response.ok) {
			const data = await response.json();
			document.getElementById('qrCodeContainer').innerHTML = `<img src="data:image/png;base64,${data.qr_code}" alt="QR Code">`;
			const otpSecret = data.otp_secret;
			const otpInput = document.createElement('input');
			otpInput.type = 'text';
			otpInput.id = 'otpInput';
			otpInput.placeholder = 'Enter OTP';
			const verifyButton = document.createElement('button');
			verifyButton.innerText = 'Verify';
			verifyButton.style.color = 'black';
			verifyButton.addEventListener('click', async function () {
				const otpCode = otpInput.value;
				try {
					const verifyResponse = await fetch(`https://${window.location.host}/auth/2fa/verify/`, {
						method: 'POST',
						headers: {
							'Authorization': 'Bearer ' + accessToken,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ otp: otpCode, otp_secret: otpSecret })
					});
					if (verifyResponse.ok) {
						alert('2FA enabled successfully.');
						document.getElementById('qrCodeContainer').innerHTML = '';
						const btn2FA = document.getElementById('btn2FA');
						btn2FA.innerText = 'Disable 2FA';
						btn2FA.removeEventListener('click', enable2FA);
						btn2FA.addEventListener('click', disable2FA);
					} else {
						alert('Failed to verify OTP. Please try again.');
					}
				} catch (error) {
					console.error('Error verifying OTP:', error);
					alert('Failed to verify OTP. Please try again.');
				}
			});
			document.getElementById('qrCodeContainer').appendChild(otpInput);
			document.getElementById('qrCodeContainer').appendChild(verifyButton);
		} else {
			alert('Failed to initiate 2FA. Please try again.');
		}
	} catch (error) {
		console.error('Error initiating 2FA:', error);
		alert('Failed to initiate 2FA. Please try again.');
	}
}

async function disable2FA(event) {
	event.preventDefault();
	const accessToken = sessionStorage.getItem('accessToken');
	try {
		const response = await fetch(`https://${window.location.host}/auth/2fa/disable/`, {
			method: 'DELETE',
			headers: {
				'Authorization': 'Bearer ' + accessToken
			}
		});
		if (response.ok) {
			alert('2FA disabled successfully.');
			const btn2FA = document.getElementById('btn2FA');
			btn2FA.innerText = 'Activate 2-factor authentication';
			btn2FA.removeEventListener('click', disable2FA);
			btn2FA.addEventListener('click', enable2FA);
		} else {
			alert('Failed to disable 2FA. Please try again.');
		}
	} catch (error) {
		console.error('Error disabling 2FA:', error);
		alert('Failed to disable 2FA. Please try again.');
	}
}

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

    fetch(`https://${window.location.host}/auth/password/update/`, {
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
	fetch(`https://${window.location.host}/auth/update/`, {
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