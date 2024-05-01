if (window.location.pathname == '/') {
    

    var dirButton = document.getElementById('dirButton');

    if (dirButton) {
        dirButton.addEventListener('click', getTargetFolder);
    }

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

    var scanMode = document.getElementById('scanMode');
    var dependencyScanBTN = document.getElementById('dependencyScan');
    var codeScanBTN = document.getElementById('codeScan');
    var fullScanBTN = document.getElementById('fullScan');
    var dirForm = document.getElementById('dirForm');

    dependencyScanBTN.addEventListener('click', function() {
        scanMode.setAttribute('value', 'dependencyScan');
        dirForm.submit();
    });

    codeScanBTN.addEventListener('click', function() {
        scanMode.setAttribute('value', 'codeScan');
        dirForm.submit();
    });

    fullScanBTN.addEventListener('click', function() {
        scanMode.setAttribute('value', 'fullScan');
        dirForm.submit();
    });

}


