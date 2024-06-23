fetch('/españa.txt').then(function(response) {
    return response.text();
}).then(function(data) {
    const content = document.createElement('p');
    content.innerText = data;
    document.body.appendChild(content);
}).catch(function(err) {
    console.err('Fetch Error:', err);
});

const userIdLabel = document.createElement('label');
userIdLabel.for = 'userName';
userIdLabel.textContent = 'Usuario: ';

const userIdInput = document.createElement('input');
userIdInput.type = 'text';
userIdInput.id = 'userName';
userIdInput.name = 'username';

const passwordLabel = document.createElement('label');
passwordLabel.for = 'password';
passwordLabel.textContent = 'Password: ';

const passwordInput = document.createElement('input');
passwordInput.type = 'password';
passwordInput.id = 'password';
passwordInput.name = 'password';

const registerButton = document.createElement('button');
registerButton.textContent = 'Registrarse';
registerButton.classList.add('register-button');
registerButton.addEventListener('click', register);


document.body.appendChild(userIdLabel);
document.body.appendChild(document.createElement('br'));
document.body.appendChild(userIdInput);
document.body.appendChild(document.createElement('br'));
document.body.appendChild(passwordLabel);
document.body.appendChild(document.createElement('br'));
document.body.appendChild(passwordInput);
document.body.appendChild(document.createElement('br'));
document.body.appendChild(registerButton);


function register() {
  const userName = document.getElementById('userName').value;
  const passwd = document.getElementById('password').value;
  if(document.getElementById('userName').value.replaceAll(/\s/g,'').length === 0 ||
     document.getElementById('password').value.replaceAll(/\s/g,'').length === 0){
        alert("Por favor complete todos los campos");
    }
  else{
        console.log(userName + ", " + passwd);
    }
}