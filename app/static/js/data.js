
document.addEventListener('DOMContentLoaded', onLoad);

function onLoad() {
    
    const pieChart = document.getElementById('pieChart');

    // Get Count Using JQuery
    $.get('/api/vulnerabilitySummary', function (data) {
        console.log(data);
        // Dictionary to store severity counts
        var severityCounts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0};
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
  

    });


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
        "critical": "#dc3545", // critical
        "high": "#fc8211", // high
        "medium": "#ffc107", // medium
        "low": "#007bff", // low
        "informational": "#24b817" // info
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
        paginationSizeSelector: [8,10,20,30,40,50],
        movableColumns: true,
        paginationCounter: "rows",
        printAsHtml: true,
        columns: [ //Define Table Columns
            { title: "id", field: "id", width: 50, hozAlign: "center" },
            { title: "name", field: "name", widthGrow: 2 },
            { title: "severity", field: "severity", hozAlign: "center", widthGrow: 1,
                formatter: function (cell, formatterParams, onRendered) {
                    var severity = cell.getValue();
                    var color = severityColors[severity];
                    cell.getElement().style.color = color;
                    cell.getElement().style.fontWeight = "bold";
                    cell.getElement().style.textTransform = "uppercase";
                    return severity; // Return the formatted cell value
                },
                
            },
            { title: "location", field: "location", hozAlign: "left", widthGrow: 3 },
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
        '#dc3545', // critical
        '#fc8211', // high
        '#ffc107', // medium
        '#007bff', // low
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