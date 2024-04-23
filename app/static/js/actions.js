var dirButton = document.getElementById('dirButton');
dirButton.addEventListener('click', getTargetFolder);

function getTargetFolder() {

    var dirInput = document.getElementById('dirInput');
    var dirReq = fetch('/getTargetFolder', {
        method: 'POST', // Set the method to POST
        headers: {
            'Content-Type': 'application/json', // Ensures the server treats the request body as JSON
        }
    })
        .then(response => response.json())
        .then(data => data)
        .then(data => dirInput.value = data);

        
}




