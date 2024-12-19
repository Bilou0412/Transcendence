document.getElementById('signin-form').addEventListener('submit', async function (event) {
    event.preventDefault();
    const email = document.getElementById('signin-email').value;
    const password = document.getElementById('signin-password').value;
    try {
        const response = await fetch('http://localhost:8443/auth/login/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        const data = await response.json();
        if (data.access) {
            const accessToken = data.access;
            const username = data.user.username;
            const userId = data.user.id;
            sessionStorage.setItem('accessToken', accessToken);
            sessionStorage.setItem('username', username);
            sessionStorage.setItem('userId', userId);
            connectWebSocket(accessToken, username, userId);
            setTimeout(() => {
                if (globalSocket && globalSocket.readyState === WebSocket.OPEN) {
                    showMainMenu();
                } else {
                    alert('Login failed. Please check your credentials.');
                }
            }, 1000);
        } else {
            alert('Login failed. Please check your credentials.');
        }
    } catch (error) {
        console.error('Error during login or WebSocket connection:', error);
        alert('Login failed. Please try again.');
    }
});

document.getElementById('signup-form').addEventListener('submit', async function (event) {
    event.preventDefault();
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    const password2 = document.getElementById('signup-password2').value;
    const username = document.getElementById('signup-username').value;
    try {
        const response = await fetch('http://localhost:8443/auth/signup/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password, password2, username })
        });
        const data = await response.json();
        if (data.access) {
            const accessToken = data.access;
            const username = data.user.username;
            const userId = data.user.id;
            sessionStorage.setItem('accessToken', accessToken);
            sessionStorage.setItem('username', username);
            sessionStorage.setItem('userId', userId);
            connectWebSocket(accessToken, username, userId);
            setTimeout(() => {
                if (globalSocket && globalSocket.readyState === WebSocket.OPEN) {
                    showMainMenu();
                } else {
                    alert('Signup failed. Please check your details.');
                }
            }, 1000);
        } else {
            alert('Signup failed. Please check your details.');
        }
    } catch (error) {
        console.error('Error during signup or WebSocket connection:', error);
        alert('Signup failed. Please try again.');
    }
});

document.getElementById('logout-button').addEventListener('click', function () {
    if (globalSocket) {
        globalSocket.close();
    }
    sessionStorage.removeItem('accessToken');
    sessionStorage.removeItem('username');
    sessionStorage.removeItem('userId');
    location.reload();
});

document.getElementById('oauth-button').addEventListener('click', function () {
    const oauthUrl = 'https://api.intra.42.fr/oauth/authorize?client_id=u-s4t2ud-6d896cbba0cf9cbd760394daeca2728498dace7f3254b04ac08fe1fc0dcc73f3&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2FzTestTools%2Fsucces.html&response_type=code';
    const popup = window.open(oauthUrl, 'OAuth Login', 'width=600,height=600');
    const interval = setInterval(function () {
        try {
            if (popup.location.href.indexOf('code=') !== -1) {
                const urlParams = new URLSearchParams(popup.location.search);
                const code = urlParams.get('code');
                if (code) {
                    fetch(`http://localhost:8443/auth/oauth/?code=${code}`, {
                        method: 'GET'
                    })
                        .then(response => response.json())
                        .then(data => {
                            if (data.access) {
                                sessionStorage.setItem('accessToken', data.access);
                                sessionStorage.setItem('refreshToken', data.refresh);
                                sessionStorage.setItem('userId', data.user.id);
                                sessionStorage.setItem('username', data.user.username);
                                connectWebSocket(data.access, data.user.username, data.user.id);
                                setTimeout(() => {
                                    if (globalSocket && globalSocket.readyState === WebSocket.OPEN) {
                                        showMainMenu();
                                    } else {
                                        alert('OAuth failed');
                                    }
                                }, 1000);
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

window.onload = function () {
    const accessToken = sessionStorage.getItem('accessToken');
    const username = sessionStorage.getItem('username');
    const userId = sessionStorage.getItem('userId');
    if (accessToken && username && userId) {
        connectWebSocket(accessToken, username, userId);
        setTimeout(() => {
            if (globalSocket && globalSocket.readyState === WebSocket.OPEN) {
                showMainMenu();
            } else {
                document.getElementById('login-signup').classList.add('active');
            }
        }, 1000);
    } else {
        document.getElementById('login-signup').classList.add('active');
    }
};
