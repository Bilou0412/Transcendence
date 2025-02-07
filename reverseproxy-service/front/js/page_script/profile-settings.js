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
				const imgElement = document.getElementById(imageElementIds);
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

document.getElementById('btn2FA').addEventListener('click', async function (event) {
	event.preventDefault();
	const accessToken = sessionStorage.getItem('accessToken');
	try {
		const response = await fetch('https://localhost:8443/auth/2fa/enable/', {
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
			//texte color
			verifyButton.style.color = 'black';
			verifyButton.addEventListener('click', async function () {
				const otpCode = otpInput.value;
				try {
					const verifyResponse = await fetch('https://localhost:8443/auth/2fa/verify/', {
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
});

document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('editBtnUsername').addEventListener('click', function () {
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
});
function toggleEditForm(fieldId) {
    const form = document.getElementById(`${fieldId}-form`);
    const span = document.getElementById(fieldId);
    const button = document.getElementById(`editBtn${capitalizeFirstLetter(fieldId)}`);
    if (form.style.display === 'none') {
        form.style.display = 'block';
        span.style.display = 'none';
        button.style.display = 'none';
    } else {
        form.style.display = 'none';
        span.style.display = 'inline';
        button.style.display = 'inline';
    }
}

function saveField(fieldId) {
    const input = document.getElementById(`${fieldId}-input`);
    const newValue = input.value;
    const span = document.getElementById(fieldId);
    span.innerText = newValue;
    toggleEditForm(fieldId);
    // Add code here to save the new value to the server if needed
}

function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}