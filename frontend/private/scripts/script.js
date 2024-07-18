fetch('/españa.txt').then(function(response) {
    return response.text();
}).then(function(data) {
    const content = document.createElement('p');
    content.innerText = data;
    document.body.appendChild(content);
}).catch(function(err) {
    console.err('Fetch Error:', err);
});


class Character{
    avatar;
    constructor(name, hp, maxHp, mov) {
        this.name = name;
        this.hp = hp;
        this.maxHp = maxHp;
        this.mov = mov;
    }
}



class User{
    listaMapas = [];
    constructor(user_name, passwd_hash) {
        this.user_name = user_name;
        this.passwd_hash = passwd_hash;
    }
}


class Tile{
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
