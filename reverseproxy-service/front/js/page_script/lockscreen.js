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

const guestBtn = document.getElementById('guestButton');
const lockscreenPage = document.getElementById('LockPage');
const homePage = document.getElementById('HomePage');
guestBtn.addEventListener('click', function() {


    homePage.classList.remove('hidden');
    homePage.classList.add('showing');

	lockscreenPage.classList.remove('showing');
	lockscreenPage.classList.add('hidden');
	// lockscreenPage.style.display = 'none';
	// homePage.style.display = 'block';
});

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
