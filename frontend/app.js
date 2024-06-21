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

const enterButton = document.createElement('button');
enterButton.textContent = 'Iniciar sesión';
enterButton.classList.add('login-button');
enterButton.addEventListener('click', onButtonClick);


document.body.appendChild(userIdLabel);
document.body.appendChild(document.createElement('br'));
document.body.appendChild(userIdInput);
document.body.appendChild(document.createElement('br'));
document.body.appendChild(passwordLabel);
document.body.appendChild(document.createElement('br'));
document.body.appendChild(passwordInput);
document.body.appendChild(document.createElement('br'));
document.body.appendChild(enterButton);



function onButtonClick() {
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




//in progress code. Paused development for now

class Character{
    avatar;
    constructor(name, hp, maxHp, mov, owner) {
        this.name = name;
        this.hp = hp;
        this.maxHp = maxHp;
        this.mov = mov;
        this.owner = owner;
    }
}

class User{
    constructor(user_name, passwd_hash) {
        this.user_name = user_name;
        this.passwd_hash = passwd_hash;
    }

}

class Dm extends User{
    idCampaignList = [];
    constructor(user_name, passwd_hash) {
        super(user_name, passwd_hash)
    }
}

class Campaign{
    idMapLists = [];
    constructor(idDm) {
        this.idDM = idDM;
    }
}

class Tile{
    tileContent; //displays what dynamic object of Character type is on top of the tile, an enemy, a character...
    constructor(posX,posY,type, diffTerr) {
        this.posX = posX;
        this.posY = posY;
        this.type = type;
        this.diffTerr = diffTerr;
    }

    checkTile(character){
        return this.type;
    }
}

class Map{
    constructor(idCampaign) {
        this.idCampaign = idCampaign;
        this.table = Array(6).fill().map(() => Array(6).fill(0));
    }

    addTile(tileOb){
        if(tileOb instanceof Tile){
            //sin terminar
        }else{
            alert("Non-Tile object was attempted to use as a Tile object")
        }
    }
}



class MovableTile extends Tile{

    constructor(posX,posY,type,diffTerr) {
        super(posX,posY,type,diffTerr);
    }

    
    moveTile(newTile){
        if(newTile.type === "ground"){
            [this.posX, newTile.posX] = [newTile.posX, this.posX];
            [this.posY, newTile.posY] = [newTile.posY, this.posY];
        }else{
            console.log("Cannot move this object there...");
        }
    }

}




casilla1 = new Tile(0,0,"ground",false);
casilla3 = new Tile(1,1,"wall",false);
casilla2 = new MovableTile(0,1,"furniture",false);

console.log(casilla1.posX + "," + casilla1.posY);
console.log(casilla2.posX + "," + casilla2.posY);
casilla2.moveTile(casilla1);
console.log(casilla1.posX + "," + casilla1.posY);
console.log(casilla2.posX + "," + casilla2.posY);
casilla2.moveTile(casilla3);
console.log(casilla3.posX + "," + casilla3.posY);
console.log(casilla2.posX + "," + casilla2.posY);