if (window.location.pathname == '/dashboard') {
    document.addEventListener('DOMContentLoaded', onLoad);
}
function onLoad() {
    
    const pieChart = document.getElementById('pieChart');

    var data = document.getElementById('data').value;
    console.log(data);
    data = JSON.parse(data);
    
    var severityCounts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "informational": 0};
    // Calculate counts for each severity
    data.forEach(function (vuln) {
        if (severityCounts[vuln.severity]) {
            severityCounts[vuln.severity]++;
        }
        else {
            severityCounts[vuln.severity] = 1;
        }
    });
    console.log(severityCounts);

        // -----------------------------------------------------
        // CARDS
        fillCards(severityCounts);
        // -----------------------------------------------------
        // TABLE
        fillTable(data)
        // -----------------------------------------------------
        // CHART
        fillChart(severityCounts);
  

    //});


}    

function fillCards(severityCounts){

    const cards = document.querySelectorAll('.card');

    // Loop through the cards
    cards.forEach(card => {
        // Get the count
        const count = card.querySelector('.count');

        // Get the header
        const header = card.querySelector('.header');

        // Get the severity
        const severity = card.id;

        count.innerHTML = severityCounts[severity];


    });
}

function fillTable(data){
    var severityColors = {
        "HIGH": "#dc3545", 
        "MEDIUM": "#fc8211", 
        "LOW": "#ffc107",  
        "informational": "#24b817" 
    };


    //create Tabulator on DOM element with id "example-table"
    var table = new Tabulator("#example-table", {
        data: data, //assign data to table
        layout: "fitColumns", //fit columns to width of table (optional)
        resizableColumnGuide: true,
        columnDefaults: {
            resizable: true,
        },
        pagination: "local",
        paginationSize: 8,
        paginationSizeSelector: [5,8,10,20,30,40,50],
        movableColumns: true,
        paginationCounter: "rows",
        printAsHtml: true,
        columns: [ //Define Table Columns
            { title: "id", field: "id", width: 50, hozAlign: "center" },
            { title: "Issue", field: "name", widthGrow: 3 }, 
            { title: "severity", field: "severity", hozAlign: "center", widthGrow: 0.5,
                formatter: function (cell, formatterParams, onRendered) {
                    var severity = cell.getValue();
                    var color = severityColors[severity];
                    cell.getElement().style.color = color;
                    cell.getElement().style.fontWeight = "bold";
                    cell.getElement().style.textTransform = "uppercase";
                    cell.getElement().style.justifyContent = "center";
                    cell.getElement().style.alignItems = "center";
                    return severity; // Return the formatted cell value
                },
                
            },
            { title: "location", field: "location", hozAlign: "left", widthGrow: 1 },
        ],
    });

    //trigger download of data.csv file
    document.getElementById("download-csv").addEventListener("click", function () {
        table.download("csv", "data.csv");
    });

    //trigger download of data.json file
    document.getElementById("download-json").addEventListener("click", function () {
        table.download("json", "data.json");
    });

    //trigger download of data.xlsx file
    document.getElementById("download-xlsx").addEventListener("click", function () {
        table.download("xlsx", "data.xlsx", { sheetName: "My Data" });
    });

    //trigger download of data.pdf file
    document.getElementById("download-pdf").addEventListener("click", function () {
        table.download("pdf", "data.pdf", {
            orientation: "portrait", //set page orientation to portrait
            title: "Example Report", //add title to report
        });
    });

    //trigger download of data.html file
    document.getElementById("download-html").addEventListener("click", function () {
        table.download("html", "data.html", { style: true });
    });

    //print button
    document.getElementById("print-table").addEventListener("click", function () {
        table.print(false, true);
    });
}

function fillChart(severityCounts){

    var labels = Object.keys(severityCounts);
    var counts = Object.values(severityCounts);

    var backgroundColors = [
        '#dc3545', // high
        '#fc8211', // medium
        '#ffc107', // low
        '#24b817', // info

    ];

    new Chart(pieChart, {
        type: 'doughnut',
        plugins: [ChartDataLabels],
        data: {
            labels: labels,
            datasets: [{
                label: 'Severity Counts',
                data: counts,
                backgroundColor: backgroundColors,
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    display: false
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom'
                },
                datalabels: {
                    formatter: (value, context) => {
                        return value;
                    },
                    color: '#fff', // color of the data labels
                    labels: {
                        title: {
                            font: {
                                weight: 'bold',
                                size: 16
                            }
                        }
                    }
                }
            }
        }
    });  
}