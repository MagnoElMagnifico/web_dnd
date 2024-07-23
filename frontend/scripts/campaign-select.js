function sendJson(url, json) {
    return fetch(url, {
        'method': 'POST',
        'headers': {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        'body': JSON.stringify(json)
        // body only necessary upon sending data
    });
}

function sendJsonGET(url) {
    return fetch(url, {
        'method': 'GET',
        'headers': {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        // body only necessary upon sending data
    });
}

async function campaignSelected(){

}

//execute this first function upon loading the page
loadCampaigns();
async function loadCampaigns(){
    try{
        const campaigns = await sendJsonGET('/campaigns');
        for(row in campaigns){
            const newR = document.createElement('tr');
            const cell = document.createElement('td');
            cell.textContent = row;
            newR.appendChild(cell);
            const constCell = document.createElement('td');
            constCell.textContent = "..?";
            newR.appendChild(constCell);
            campTable.appendChild(newR);
        }
    }catch (error){
        console.error('Error:', error);
    }
}

const campTable = document.getElementById("campaignsT");
const rows = campTable.getElementsByTagName('tr');
for(let i = 1; i < rows.length; i++){
    rows[i].addEventListener('click',(event)=>{
        event.preventDefault();
        campaignSelected(rows[i]);
    })
}

campTable.addEventListener("submit", (event) => {
   event.preventDefault();

});