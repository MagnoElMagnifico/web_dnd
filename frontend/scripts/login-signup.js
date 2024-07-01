function sendJson(url, json) {
    return fetch(url, {
        'method': 'POST',
        'headers': {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        'body': JSON.stringify(json)
    });
}

async function login(inputUsername, inputPassword) {
    const errorLabel = document.getElementById('login-error')

    try {
        const response = await sendJson('/api/login', {
            'username': inputUsername,
            'password': inputPassword,
        });

        if (!response.ok) {
            const result = await response.json();
            console.error(result['error'] + ': ' + result['description']);
            errorLabel.textContent = result['description'];
            errorLabel.hidden = false;
            return;
        }

        errorLabel.hidden = true;

        // On success, the server must set the session cookie, so we reload the
        // page to load the user's content.
        window.location.reload();

    } catch (error) {
        console.error('Error:', error);
        errorLabel.textContent = 'Ha sucedido un error inesperado';
        errorLabel.hidden = false;
    }
}

async function signup(inputUsername, inputPassword1, inputPassword2) {
    const errorLabel = document.getElementById('signup-error')

    try {
        // TODO: Password strength checks
        // TODO: Username format checks

        if (inputPassword1 !== inputPassword2) {
            errorLabel.textContent = 'Las dos contraseñas no coinciden';
            errorLabel.hidden = false;
            return;
        }

        const response = await sendJson('/api/signup', {
            'username': inputUsername,
            'password': inputPassword1,
        });


        if (!response.ok) {
            // Show the server's error
            const result = await response.json();

            console.error(result['error'] + ': ' + result['description']);
            errorLabel.textContent = result['description'];
            errorLabel.hidden = false;
            return;
        }

        errorLabel.hidden = true;

        // On success, the server must set the session cookie, so we reload the
        // page to load the user's content.
        window.location.reload();

    } catch (error) {
        console.error('Error:', error);
        errorLabel.textContent = 'Ha sucedido un error inesperado';
        errorLabel.hidden = false;
    }
}

const loginForm = document.getElementById('login');
loginForm.addEventListener('submit', (event) => {
    event.preventDefault();
    login(
        loginForm['input-username'].value,
        loginForm['input-password'].value);
});


const signupForm = document.getElementById('signup');

// // TODO: Check the password strength
// signupForm['input-password1'].addEventListener('change', (event) => {
//     console.log('change');
//     console.log(event);
// });

signupForm.addEventListener('submit', (event) => {
    event.preventDefault();
    signup(
        signupForm['input-username'].value,
        signupForm['input-password1'].value,
        signupForm['input-password2'].value);
});

