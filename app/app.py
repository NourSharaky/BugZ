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
def dashboard():
    global parser
    if parser is None:
        abort(404)

    if request.method == 'GET':
        # Retrieve data from session or use default values
        projectName = session.get('projectName', 'Default Project Name')
        projectPath = session.get('projectPath', None)
        pythonFiles = session.get('pythonFiles', [])
        requirementsFile = session.get('requirementsFile', "")

        files = []
        for file in pythonFiles:
            file = str(file).split(projectPath)[-1]
            files.append(file)

        if requirementsFile != None and requirementsFile != "":
            requirementsFile = str(requirementsFile).split(projectPath)[-1]
        
        return render_template('dashboard.html', projectName=projectName, pythonFiles=files, requirementsFile=requirementsFile)
    else:
        # POST request: update session data
        projectName = request.form['projectName']
        projectPath = request.form['projectPath']
        
        session['projectName'] = projectName  # Store projectName in session
        session['projectPath'] = projectPath
        parser.projectFolder = projectPath
        
        pythonFiles, requirementsFile = parser.scanDirectory()

        # Store these in the session as well
        session['pythonFiles'] = pythonFiles
        session['requirementsFile'] = requirementsFile

        return redirect(url_for('dashboard'))

@app.route("/api/severitySummary")
def severitySummary():
    global parser
    if parser is None:
        abort(404)

    # Call ImportedLibScan

    # Call FileVulnScan to get the vulnerabilities
    
    # Build Response JSON
        # Categorize into the Severity Summary 


# TODO: Implement the severity summary
    severitySummary = {
        "critical": 1,
        "high": 10,
        "medium": 20,
        "low": 2,
        "info": 0
    }
    return jsonify(severitySummary)

@app.route("/api/vulnerabilitySummary")
def vulnTable():
    global parser
    if parser is None:
        abort(404)

# TODO: Implement the severity summary
    vulnTable = [
        {"id": 1, "severity": "critical", "name": "SQL Injection", "location": "file1.py"},
        {"id": 2, "severity": "critical", "name": "SQL Injection", "location": "file1.py"},
        {"id": 3, "severity": "high", "name": "SQL Injection", "location": "file1.py"},
        {"id": 4, "severity": "high", "name": "SQL Injection", "location": "file1.py"},
        {"id": 5, "severity": "high", "name": "SQL Injection", "location": "file1.py"},
        {"id": 6, "severity": "high", "name": "SQL Injection", "location": "file1.py"},
        {"id": 7, "severity": "high", "name": "SQL Injection", "location": "file1.py"},
        {"id": 8, "severity": "medium", "name": "SQL Injection", "location": "file1.py"},
        {"id": 9, "severity": "medium", "name": "SQL Injection", "location": "file1.py"},
        {"id": 10, "severity": "low", "name": "SQL Injection", "location": "file1.py"},
        {"id": 11, "severity": "informational", "name": "SQL Injection", "location": "file1.py"},
        {"id": 12, "severity": "informational", "name": "SQL Injection", "location": "file1.py"},
        {"id": 13, "severity": "informational", "name": "SQL Injection", "location": "file1.py"},
    ]


    return jsonify(vulnTable)



if __name__ == '__main__':
    app.run(debug=True)
