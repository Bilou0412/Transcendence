//////////////////////////// Show/Hide Login Form ////////////////////////////
// Get references to the login button and login form
const loginButton = document.getElementById('showLoginForm');
const loginForm = document.getElementById('loginFormContainer');

// Add click event listener to the login button
loginButton.addEventListener('click', function() {
	// Toggle the 'show' class to display/hide the login form
	loginForm.classList.toggle('show');
	
	// Set button opacity based on form visibility
	if (loginForm.classList.contains('show')) {
		loginButton.style.opacity = '1';
	} else {
		loginButton.style.opacity = '0.5';  // or whatever your default opacity is
	}
});

// Function to dynamically load a script
function loadScript(src) {
	const script = document.createElement('script');
	script.src = src;
	document.body.appendChild(script);
}

const guestBtn = document.getElementById('guestButton');
const lockscreenPage = document.getElementById('LockPage');
const homePage = document.getElementById('HomePage');

guestBtn.addEventListener('click', function () {
	document.body.style.backgroundImage = "url('../../texture/backSefir.jpeg')";
	// Transition between pages
	homePage.classList.remove('hidden');
	homePage.classList.add('showing');

	lockscreenPage.classList.remove('showing');
	lockscreenPage.classList.add('hidden');

	// Dynamically load the other scripts
	loadScript('../js/page_script/clock.js'); // Load clock.js
	loadScript('../js/router.js', true); // Load router.js as a module

	// Optionally, remove this script after it has done its work
	const lockscreenScript = document.querySelector('script[src="../js/page_script/lockscreen.js"]');
	if (lockscreenScript) lockscreenScript.remove();
});

// Function to dynamically load a script
function loadScript(src, isModule = false) {
	const script = document.createElement('script');
	script.src = src;
	if (isModule) script.type = 'module'; // Add type="module" if needed
	document.body.appendChild(script);
}

//////////////////////////// Show/Hide Register Form ////////////////////////////
// Get references to the register button and register form
const registerButton = document.getElementById('showRegisterForm');
const registerClose = document.getElementById('closeRegister');
const registerForm = document.getElementById('registerFormContainer');

// Add click event listener to the register button
registerButton.addEventListener('click', function() {
	// Toggle the 'show' class to display/hide the register form
	registerForm.classList.toggle('show');
});

registerClose.addEventListener('click', function() {
	// Toggle the 'show' class to display/hide the register form
	registerForm.classList.toggle('show');
});

//////////////////////////// Password Validation ////////////////////////////
const submitRegiBtn = document.getElementById('submitRegiBtn');
const pswrdRegiField = document.getElementById('pswrdRegiField');
const repswrdRegiField = document.getElementById('repswrdRegiField');

pswrdRegiField.onfocus = function() {
	document.getElementById('pass_message').style.display = 'block';
};

pswrdRegiField.onblur = function() {
	document.getElementById('pass_message').style.display = 'none';
};

let pass_ok	= [false, false, false, false, false];
//////////////////////////// Password Security Validation ////////////////////////////
pswrdRegiField.addEventListener('input', function() {
	const pass_message = document.getElementById('pass_message');
	const lowerCaseLetters = /[a-z]/g;
	const upperCaseLetters = /[A-Z]/g;
	const numbers = /[0-9]/g;
	const specialCharacters = /[!@#$%^&*(),.?":{}|<>_\-\/\\[\]`~]/g;

	if (pswrdRegiField.value.match(lowerCaseLetters)) {
		pass_message.children[0].style.color = 'green';
		pass_ok[0] = true;
	} else {
		pass_message.children[0].style.color = 'red';
		pass_ok[0] = false;
	}

	if (pswrdRegiField.value.match(upperCaseLetters)) {
		pass_message.children[1].style.color = 'green';
		pass_ok[1] = true;
	} else {
		pass_message.children[1].style.color = 'red';
		pass_ok[1] = false;
	}

	if (pswrdRegiField.value.match(numbers)) {
		pass_message.children[2].style.color = 'green';
		pass_ok[2] = true;
	} else {
		pass_message.children[2].style.color = 'red';
		pass_ok[2] = false;
	}

	if (pswrdRegiField.value.match(specialCharacters)) {
		pass_message.children[3].style.color = 'green';
		pass_ok[3] = true;
	} else {
		pass_message.children[3].style.color = 'red';
		pass_ok[3] = false;
	}

	if (pswrdRegiField.value.length >= 8) {
		pass_message.children[4].style.color = 'green';
		pass_ok[4] = true;
	} else {
		pass_message.children[4].style.color = 'red';
		pass_ok[4] = false;
	}
});

//////////////////////////// Password Matching ////////////////////////////
submitRegiBtn.addEventListener('click', function() {
	if (pass_ok.some(value => value === false)) {
		pswrdRegiField.setCustomValidity('Password does not meet the requirements');
	}
	if (pswrdRegiField.value !== repswrdRegiField.value) {
		pswrdRegiField.setCustomValidity('Passwords do not match');
		console.log(pswrdRegiField.value);
		console.log(repswrdRegiField.value);
	}
});

////////////////////////// Post Login Form Data ////////////////////////////
document.getElementById('loginForm').addEventListener('submit', function(event) {
   event.preventDefault();
   const email = document.getElementById('usrnameField').value;
   const password = document.getElementById('pswrdField').value;
   const otp = document.getElementById('2faField').value;
   console.log('Email:', email);
   console.log('Password:', password);
   console.log('OTP:', otp);
   
   fetch('https://localhost:8443/auth/login/', {
       method: 'POST',
       headers: {
           'Content-Type': 'application/json'
       },
       body: JSON.stringify({
           email: email,
           password: password,
           otp: otp // Correctly send the OTP value
       })
   }).then(response => {
       if (response.ok) {
           // Handle successful login
           response.json().then(data => {
            	console.log('Login successful:', data);
				sessionStorage.setItem('accessToken', data.access);
            	sessionStorage.setItem('refreshToken', data.refresh);
            	sessionStorage.setItem('userId', data.user.id);
            	sessionStorage.setItem('username', data.user.username);
				sessionStorage.setItem('email', data.user.email);
				
				// Transition to home page
				homePage.classList.remove('hidden');
				homePage.classList.add('showing');
				lockscreenPage.classList.remove('showing');
				lockscreenPage.classList.add('hidden');
				lockLogo.style.display = 'none';
				// alert('Login successful');
            	
				
				// Dynamically load the other scripts
				loadScript('../js/page_script/clock.js'); // Load clock.js
				loadScript('../js/router.js', true); // Load router.js as a module
           });
       } else {
           console.log('Login failed:', response.statusText);
           // Handle login error
       }
   }).catch(error => {
       console.error('Network error:', error);
       // Handle network error
   });
});

////////////////////////// Forgot Password ////////////////////////////
document.querySelector('.forgot-password').addEventListener('click', function(event) {
	event.preventDefault();
	const email = document.getElementById('usrnameField').value;
	if (!email) {
		alert('Please enter your email address.');
		return;
	}
	
	fetch('https://localhost:8443/auth/password/reset/', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ email: email })
	}).then(response => {
		if (response.ok) {
			alert('Password reset email sent. Please check your inbox.');
		} else {
			response.json().then(data => {
				const errorMessage = Object.values(data).flat().join('\n');
				alert(errorMessage || 'Failed to send password reset email.');
			});
		}
	}).catch(error => {
		console.error('Network error:', error);
		alert('Network error. Please try again later.');
	});
});

////////////////////////// Post Register Form Data ////////////////////////////
document.querySelector('#registerFormContainer form').addEventListener('submit', function(event) {
	event.preventDefault();
	const username = document.getElementById('usrnameRegiField').value;
	const password = document.getElementById('pswrdRegiField').value;
	const password2 = document.getElementById('repswrdRegiField').value;
	const email = document.getElementById('emailRegiField').value;
	console.log('Username:', username);
	console.log('Password:', password);
	console.log('Confirm Password:', password2);
	console.log('Email:', email);

	fetch('https://localhost:8443/auth/signup/', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			username: username,
			password: password,
			password2: password2,
			email: email
		})
	}).then(response => {
		if (response.ok) {
			// Handle successful registration
			response.json().then(data => {
				console.log('Registration successful:', data);
				alert(data.message || 'Registration successful! Please verify your email.');
				// Redirect to login page or perform other actions
			});
		} else {
			response.json().then(data => {
				console.log('Registration failed:', data);
				const errorMessage = Object.values(data).flat().join('\n');
				alert(errorMessage || 'Registration failed.');
			});
		}
	}).catch(error => {
		console.error('Network error:', error);
		alert('Network error. Please try again later.');
	});
});



const log42Button = document.getElementById('log42Button');

log42Button.addEventListener('click', function () {
	const oauthUrl = 'https://api.intra.42.fr/oauth/authorize?client_id=u-s4t2ud-6d896cbba0cf9cbd760394daeca2728498dace7f3254b04ac08fe1fc0dcc73f3&redirect_uri=https%3A%2F%2Flocalhost%3A8443%2Fsucces%2F&response_type=code';
	const popup = window.open(oauthUrl, 'OAuth Login', 'width=600,height=600');
	const interval = setInterval(function () {
		try {
			if (popup.location.href.indexOf('code=') !== -1) {
				const urlParams = new URLSearchParams(popup.location.search);
				const code = urlParams.get('code');
				if (code) {
					fetch(`https://localhost:8443/auth/oauth/?code=${code}`, {
						method: 'GET'
					})
					.then(response => response.json())
					.then(data => {
						if (data.access) {
							sessionStorage.setItem('accessToken', data.access);
							sessionStorage.setItem('refreshToken', data.refresh);
							sessionStorage.setItem('userId', data.user.id);
							sessionStorage.setItem('username', data.user.username);
							sessionStorage.setItem('email', data.user.email);
							
							// Transition to home page
							homePage.classList.remove('hidden');
							homePage.classList.add('showing');
							lockscreenPage.classList.remove('showing');
							lockscreenPage.classList.add('hidden');
							lockLogo.style.display = 'none';
							
							// Dynamically load the other scripts
							loadScript('../js/page_script/clock.js'); // Load clock.js
							loadScript('../js/router.js', true); // Load router.js as a module
						} else {
							alert('OAuth failed');
						}
					})
					.catch(error => {
						console.error('Error during OAuth request:', error);
					});
					popup.close();
					clearInterval(interval);
				}
			}
		} catch (error) {
			console.error('Error checking popup URL:', error);
		}
	}, 1000);
});


////////////////////////// Logout ////////////////////////////
const logoutButton = document.getElementById('logoutButton');
logoutButton.addEventListener('click', function() {
	sessionStorage.clear();
	window.location.reload();
});

////////////////////////// Auto-Login ////////////////////////////
async function autoLogin() {
    const accessTokenLogin = sessionStorage.getItem('accessToken');

    if (!accessTokenLogin) {
        console.log('No access token found.');
        return;
    }
	try {
		const response = await fetch('https://localhost:8443/auth/token/validate/', {
			method: 'POST', // Ensure it's a POST request
			headers: {
				'Authorization': 'Bearer ' + accessTokenLogin
			},
		});
		if (response.ok) {
			console.log('Token is valid.');

			// Transition to home page
			homePage.classList.remove('hidden');
			homePage.classList.add('showing');
			lockscreenPage.classList.remove('showing');
			lockscreenPage.classList.add('hidden');
			lockLogo.style.display = 'none';

			// Dynamically load the other scripts
			loadScript('../js/page_script/clock.js'); // Load clock.js
			loadScript('../js/router.js', true); // Load router.js as a module
		} else {
			console.log('Token validation failed:', response.status);
			// Handle token expiration (optional: refresh token logic)
		}
	} catch (error) {
		console.error('Network error:', error);
		// Handle network error
	}
}

autoLogin();
