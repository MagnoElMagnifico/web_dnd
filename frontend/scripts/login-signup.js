async function login(input_username, input_password) {
    const response = await fetch('/api/login', {
        method: 'POST',
        body: JSON.stringify({
            'username': input_username,
            'password': input_password
        })
    });

    const data = await response.text();
    console.log(data);
}

const login_form = document.getElementById('login');

login_form.addEventListener('submit', (event) => {
    event.preventDefault();
    login(login_form['input_username'].value, login_form['input_password'].value).then();
});

