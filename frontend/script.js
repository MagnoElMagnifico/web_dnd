fetch('/españa.txt').then(function(response) {
    return response.text();
}).then(function(data) {
    const content = document.createElement('p');
    content.innerText = data;
    document.body.appendChild(content);
}).catch(function(err) {
    console.err('Fetch Error:', err);
});
