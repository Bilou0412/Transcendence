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
               // Redirect to home page or perform other actions
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