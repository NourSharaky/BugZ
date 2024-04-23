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
    # files = ['requirements.txt', 'app.py', 'aes.py']


    return render_template('index.html') #, files = files)

@app.post('/getTargetFolder')
def getTargetFolder():
    global parser

    print("Getting Target Folder")

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
        pythonFiles = session.get('pythonFiles', [])
        requirementsFile = session.get('requirementsFile', "")
        return render_template('dashboard.html', projectName=projectName, pythonFiles=pythonFiles, requirementsFile=requirementsFile)
    else:
        # POST request: update session data
        projectName = request.form['projectName']
        projectPath = request.form['projectPath']
        
        session['projectName'] = projectName  # Store projectName in session
        parser.projectFolder = projectPath
        
        pythonFiles, requirementsFile = parser.scanDirectory()
        print(requirementsFile)
        # Store these in the session as well
        session['pythonFiles'] = pythonFiles
        session['requirementsFile'] = requirementsFile

        return redirect(url_for('dashboard'))
if __name__ == '__main__':
    app.run(debug=True)
