# app.py
from flask import Flask, render_template, jsonify, abort, request, redirect, url_for, session
from tkinter import Tk     
from tkinter.filedialog import askdirectory
from classes.PythonParser import PythonParser
import subprocess 


app = Flask(__name__)
parser = None
# PythonParser(logging=False, projectFolder=projectFolder)
app.secret_key = 'super secret'  # Set a secret key for the session 

@app.route('/')
def index():

    return render_template('index.html') 

@app.post('/getTargetFolder')
def getTargetFolder():
    global parser

    result = subprocess.run(['python', 'selectDirectory.py'], capture_output=True, text=True)
    if result.stdout:
        projectFolder = result.stdout.strip()  # Return the directory path, stripping any extra whitespace
    else:
        projectFolder = None
        abort(404)  # No directory was selected or an error occurred

    parser = PythonParser(logging=False, projectFolder=projectFolder)
    return jsonify(projectFolder)

@app.route("/dashboard",methods=['POST','GET'])
def dashboard(scanMode="fullScan"):
    global parser
    if parser is None:
        abort(404)

    if request.method == 'GET':
        # Retrieve data from session or use default values
        projectName = session.get('projectName', 'Default Project Name')
        projectPath = session.get('projectPath', None)
        pythonFiles = session.get('pythonFiles', [])
        requirementsFile = session.get('requirementsFile', "")
        scanMode = session.get('scanMode', "")
        

        files = []
        for file in pythonFiles:
            file = str(file).split(projectPath)[-1]
            files.append(file)

        if requirementsFile != None and requirementsFile != "":
            requirementsFile = str(requirementsFile).split(projectPath)[-1]
        
        if scanMode == "dependencyScan":
            scanOutput = parser.dependencyScan()
            template = 'dependencyScan.html'
            vulnTable = None
        elif scanMode == "codeScan":
            scanOutput = parser.codeScan()
            template = 'codeScan.html'
            vulnTable = formatVulnTable(scanOutput)
        elif scanMode == "fullScan":
            DependenciesScanOutput, scanOutput = parser.fullScan()
            vulnTable = formatVulnTable(scanOutput, DependenciesScanOutput)
            template = 'fullScan.html'
        else:
            scanOutput = None
            template = '404.html'

        
        return render_template(template,projectPath=projectPath ,projectName=projectName, pythonFiles=files, requirementsFile=requirementsFile, scanOutput=scanOutput, vulnTable=vulnTable, DependenciesScanOutput=DependenciesScanOutput)


    else:
        # POST request: update session data
        projectName = request.form['projectName']
        projectPath = request.form['projectPath']
        scanMode = request.form['scanMode']
        
        session['projectName'] = projectName  # Store projectName in session
        session['projectPath'] = projectPath
        session['scanMode'] = scanMode
        parser.projectFolder = projectPath
        
        pythonFiles, requirementsFile = parser.scanDirectory()

        # Store these in the session as well
        session['pythonFiles'] = pythonFiles
        session['requirementsFile'] = requirementsFile
        
        return redirect(url_for('dashboard'))

def formatVulnTable(CodeScanOutput, DependencyScanOutput=None):
    vulnTable = []
    vulnCounter = 0
    
    for file in CodeScanOutput['Files']:
        if file == "Total Metrics":
            continue

        for vuln in CodeScanOutput['Files'][file]['results']:
            vulnCounter += 1
        
            if vuln['issue_severity'] == "UNDEFINED":
                vuln['issue_severity'] = "informational"

            row = {
                "id": vulnCounter,
                "severity": vuln['issue_severity'],
                "name": vuln['issue_text'],
                "location": file.split(parser.projectFolder)[-1],
            }

            vulnTable.append(row)
    
    if DependencyScanOutput:
        if DependencyScanOutput['Requirements']:
            for vuln in DependencyScanOutput['Requirements']:
                vulnCounter += 1

                row = {
                    "id": vulnCounter,
                    "severity": "LOW",
                    "name": DependencyScanOutput['Requirements'][vuln]['advisory'],
                    "location": "requirements.txt",
                }

                vulnTable.append(row)
        if DependencyScanOutput['Missing Versions']:
            for vuln in DependencyScanOutput['Missing Versions']:
                vulnCounter += 1

                row = {
                    "id": vulnCounter,
                    "severity": "informational",
                    "name": f"The detected {vuln} library has vulnerabilities in certain versions.",
                    "location": "requirements.txt",
                }

                vulnTable.append(row)
        if DependencyScanOutput['Imports']:
            for file in DependencyScanOutput['Imports']:
                for vuln in DependencyScanOutput['Imports'][file]:
                    vulnCounter += 1

                    row = {
                        "id": vulnCounter,
                        "severity": "informational",
                        "name": f"The detected {vuln} library has vulnerabilities in certain versions.",
                        "location": file.split(parser.projectFolder)[-1],
                    }

                    vulnTable.append(row)
        
    output = jsonify(vulnTable).data
    
    return output.decode('utf-8')


if __name__ == '__main__':
    app.run(debug=True, port=5001)
