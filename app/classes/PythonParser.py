# Used to parse the code and get the syntax tree
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
from pprint import pprint
from termcolor import colored
import json,re,os
import subprocess
from dotenv import load_dotenv
import os
from classes.AICodeReviewer import AICodeReviewer

class PythonParser:
    # ---------------------------------- Initialization ----------------------------------
    def __init__(self, targetFile=None, targetReqFile=None, logging=False, projectFolder=None, AIEnabled=False):
        """
        Initialize the VulnerabilityScanner class.

        Args:
            targetFile (str, optional): Path to the target file to be scanned. Defaults to None.
            targetReqFile (str, optional): Path to the target requirements file to be scanned. Defaults to None.
            logging (bool, optional): Flag indicating whether logging should be enabled. Defaults to False.
            projectFolder (str, optional): Path to the project folder. Defaults to None.

        Attributes:
            language (Language): Instance of the Language class initialized with the language of the target file.
            targetFile (str): Path to the target file to be scanned.
            targetReqFile (str): Path to the target requirements file to be scanned.
            parser (Parser): Instance of the Parser class.
            sourceCode (str): Source code of the target file.
            tree (Tree): Abstract syntax tree representation of the source code.
            vulnDBFileName (str): Path to the file containing the vulnerability database.
            vulnDB (dict): Dictionary containing vulnerabilities loaded from the database file.
            fullVulnDBFileName (str): Path to the file containing the full vulnerability database.
            fullVulnDB (dict): Dictionary containing full vulnerabilities loaded from the database file.
            logging (bool): Flag indicating whether logging is enabled.
            projectFolder (str): Path to the project folder.
        """

        self.language = Language(tspython.language(), "python")
        self.targetFile = targetFile
        self.targetReqFile = targetReqFile
        self.parser = Parser()
        self.parser.set_language(self.language)
        self.sourceCode = None
        self.tree = None
        self.vulnDBFileName = 'db\\insecure.json'
        self.vulnDB = self.LoadDB(self.vulnDBFileName)
        self.fullVulnDBFileName = 'db\\insecure_full.json'
        self.fullVulnDB = self.LoadDB(self.fullVulnDBFileName)
        self.logging = logging
        self.projectFolder = projectFolder  
        self.AIEnabled = AIEnabled

    # ---------------------------------- Directory Scanning ----------------------------------

    def scanDirectory(self):
        """
        Scans the target directory for Python files and requirements.txt file.
        """
        if self.logging:
            print(colored("Target Project Directory: ", "green") + self.projectFolder + "\n----------------------")
        pythonFiles = []

        ignore_dirs = ['Lib']
        
        requirementsFile = None
        
        # Walking through the directory and its subdirectories
        for root, dirs, files in os.walk(self.projectFolder):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]

            for file in files:
                if file.endswith('.py'):
                    pythonFiles.append(os.path.join(root, file))
                elif file == 'requirements.txt':
                    requirementsFile= os.path.join(root, file)
                    self.targetReqFile = requirementsFile
        
        if self.logging:
            print(colored("Target Requirements File: ", "green") + self.targetReqFile)
            print(colored("Target Python Files: ", "green"))
            pprint(pythonFiles)
            print("\n----------------------")


        return pythonFiles, requirementsFile
    
    # ---------------------------------- Parsing ----------------------------------

    def parseFile(self):
        """
        Parse the target file and generate the syntax tree.
        """

        with open(self.targetFile, "rb") as file:
            self.sourceCode = file.read()
        self.tree = self.parser.parse(self.sourceCode)

    def defaultParse(self, advanced=False):
        """
        Parse the target file and capture the basic elements.
        """

        queries = {
            "Imports": "(import_statement) @importStatement",
            "Imports from": "(import_from_statement) @importFromStatement",
            "Imports Functions": "(import_from_statement name: (dotted_name) @importFromFunctions)",
            "Class Definitions": "(class_definition) @classDefinition",
            "Function Definitions": "(function_definition) @functionDefinition",
            "Function Names": "(function_definition name: (identifier) @functionName)",
            "Assignments": "(assignment) @assignment",
            "Strings": "(string) @string",
            "Comments": "(comment) @comment",
        }

        if advanced:
            queries["Imports Names"] = "(import_statement (dotted_name) @importName)"
            queries["Imports from Names"] = "(import_from_statement module_name: (dotted_name) @importFromName)"
        return self.multiQuery(queries)

    def query(self, queryString):
        """
        Execute the query on the syntax tree and return the captured data.

        Args:
            queryString (str): Query string to be executed on the syntax tree.
        """
        query = self.language.query(queryString)
        return query.captures(self.tree.root_node)

    def multiQuery(self, queries):
        """
        Execute the queries on the syntax tree and parse the captured data.

        Args:
            queries (dict): Dictionary containing the title and query string to be executed.
        """

        parsedFile = {}

        for title, query in queries.items():
            captured = self.query(query)

            if self.logging:
                self.printCaptured(title, captured)

            parsedFile[title] = []

            # Grabb the text from the captured data
            for i in captured:
                parsedFile[title].append(i[0].text.decode("utf-8"))
            
        return parsedFile

    def printCaptured(self, title, captured):
        """
        Print the captured data along with the title.
        
        Args:
            title (str): Title to be printed.
            captured (list): List of captured data.
        """

        print(colored(title, "red"))
        print(colored("Captured:", "green"), len(captured), "occurrences")
        for i in captured:
            # print(i[1], i[0].start_point, i[0].end_point, i[0].text)
            print(i[0].text.decode("utf-8"))
        print(colored("-----------------------------------------------------------------------","white"))

    # ---------------------------------- Vulnerability Scanning ----------------------------------

    # Requirements

    def LoadDB(self, DBName):
        """
        Load the database from the specified file.

        Args:
            DBName (str): Path to the database file.
        """
        with open(DBName, 'r') as json_file:
            db = json.load(json_file) 

        return db

    def requirementsParse(self, location):
        """
        Parse the requirements file and extract the package names and versions.

        Args:
            location (str): Path to the requirements file.
        """

        with open(location, "r") as file:
            lines = file.readlines()

        requirements = {}

        for line in lines:
            line = line.strip()

            if line.startswith("#"):
                continue
            if line == "":
                continue
            if "==" in line:
                package, version = line.split("==")
                requirements[package] = version
            else:
                requirements[line] = None
        
        return requirements
            
    def requirementsFileVulnScan(self):
        """
        Check if the libraries in the requirements file are vulnerable.
        """
        vulnLibs = {}
        # Define a regular expression pattern to match the operator and the value
        pattern = r'(==|[<>]=?)([0-9a-zA-Z.]+)'

        if self.logging:
            print(colored("Vulnerable Libraries Detected:", "red"))

        requirements = self.requirementsParse(self.targetReqFile)
        
        LibsMissingVersion = {}

        for RequiredLib in requirements:
            if RequiredLib in self.vulnDB:
                vulnLibVersions = self.vulnDB[RequiredLib]
                ReqLibVersion = requirements[RequiredLib]

                if ReqLibVersion is None:
                    RequiredLib = RequiredLib.lower()
                    
                    if RequiredLib in self.vulnDB:
                    # store name and versions in vulndb
                        versions = self.vulnDB[RequiredLib]
                        LibsMissingVersion[RequiredLib] = versions
                    continue

                # Check if the required version falls within any of the vulnerable version ranges
                is_vulnerable = False
                for vulnVersionRange in vulnLibVersions:
                    vulnVersions = vulnVersionRange
                    conditions = vulnVersions.split(",")
                    
                    # check if the required version meets the conditions
                    for condition in conditions:
                        operator, version = re.match(pattern, condition).groups()

                        if operator == "<" and ReqLibVersion < version:
                            is_vulnerable = True
                        elif operator == "<=" and ReqLibVersion <= version:
                            is_vulnerable = True
                        elif operator == ">" and ReqLibVersion > version:
                            is_vulnerable = True
                        elif operator == ">=" and ReqLibVersion >= version:
                            is_vulnerable = True
                        elif operator == "==" and ReqLibVersion == version:
                            is_vulnerable = True
                        else:
                            is_vulnerable = False                                
                if is_vulnerable:

                    vulnLibs[RequiredLib] = {"Current Version" : requirements[RequiredLib], "Vulnerable Range" : conditions} 
                    
                    if self.logging:
                        print(RequiredLib, ReqLibVersion, "is vulnerable to attacks", conditions)
        return vulnLibs, LibsMissingVersion

    def requirementsFileVulnFullScan(self):
        """
        Check if the libraries in the requirements file are vulnerable.
        """
        vulnLibs , _ = self.requirementsFileVulnScan()
        output = {}
        # print(vulnLibs)
        for vulnLibName in vulnLibs.keys():
            if vulnLibName in self.fullVulnDB.keys():
                vulnerableRange = vulnLibs[vulnLibName]["Vulnerable Range"]
                vulnerableRange = ','.join(vulnerableRange)

                for i in range(len(self.fullVulnDB[vulnLibName])):
                    if vulnerableRange == self.fullVulnDB[vulnLibName][i]["v"]:
                    
                       self.fullVulnDB[vulnLibName][i]["Current Version"] = vulnLibs[vulnLibName]["Current Version"]
                       output[vulnLibName] = self.fullVulnDB[vulnLibName][i]
        return output              

    # Imports
                  
    def importsScan(self):
        """
        Check if the imported libraries are vulnerable.
        """
        # checks if an imported library is not in requirements.txt and is vulnerable
        query = {
            "Imports Names": "(import_statement (dotted_name) @importName)",
            "Imports from Names": "(import_from_statement module_name: (dotted_name) @importFromName)"
            }
        queryOutput = self.multiQuery(query)

        imports = queryOutput["Imports Names"] + queryOutput["Imports from Names"]

        vulnLibs = {}

        requirements = self.requirementsParse(self.targetReqFile)
        # requirements keys to lower
        requirements = [req.lower() for req in requirements.keys()]

        for importedLib in imports:
            importedLib = importedLib.split(".")[0].lower()
            
            if not (importedLib in requirements):
                if importedLib in self.vulnDB:
                    # store name and versions in vulndb
                    versions = self.vulnDB[importedLib]
                    vulnLibs[importedLib] = versions

        return vulnLibs

    def pyFilesImportsScan(self):
        """
        Scan the Python files in the target directory for vulnerable imports.
        """

        pythonFiles , _= self.scanDirectory()

        output = {}

        for pythonFile in pythonFiles:
            self.targetFile = pythonFile
            self.parseFile()
            vulnerableImports = self.importsScan()

            if len(vulnerableImports) > 0:
                output[pythonFile] = vulnerableImports

        return output

    # Python Files

    def pyFilesGeneralScan(self):
        files , _ = self.scanDirectory()

        output = {}
        total_metrics = {
            'SEVERITY.HIGH': 0,
            'SEVERITY.MEDIUM': 0,
            'SEVERITY.LOW': 0,
            'SEVERITY.UNDEFINED': 0,
        }

        getRecommendation = {}

        for file in files:
            # Create a Thread for each file and run bandit for that file
            # Use the bandit API to get the results
           # Run Bandit using subprocess
            bandit = subprocess.Popen(["python", "-m", "bandit", "-f", "json", file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Get output as a single string
            json_out = json.loads(bandit.stdout.read().decode())

            file_metrics = json_out['metrics']['_totals']
           
            # Sum up the metrics
            for metric , _ in total_metrics.items():
                total_metrics[metric] += file_metrics[metric]
            
            # remove metrics & errors from json
            del json_out['metrics']
            del json_out['errors']

            if len(json_out["results"]) < 1 :
                continue

            # Sorting the results based on severity
            json_out["results"].sort(key=lambda x: {"HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["issue_severity"], 4))

            # remove attriutes from json
            for res in json_out["results"]:
                del res["more_info"]
                del res["test_id"] 
                del res["test_name"]
                del res["col_offset"]
                del res["end_col_offset"]
                del res["issue_confidence"]
                del res["line_number"]
                del res["line_range"]

                getRecommendation = {"code": json_out["results"][0]["code"], "issue_text": json_out["results"][0]["issue_text"]}
                if self.AIEnabled:
                    recommendation = self.getAIVulnRecommendation(getRecommendation)
                    res["recommendation"] = recommendation
                else:
                    res["recommendation"] = "Recommendation not available"

            output[file] = json_out
        
        output["Total Metrics"] = total_metrics
        print(output)
        return output

    # ---------------------------------- Vulnerability Scanning Modes ----------------------------------

    def dependencyScan(self):
        output = {}

        output["Requirements"] = self.requirementsFileVulnFullScan()
        _ , output["Missing Versions"] = self.requirementsFileVulnScan()
        output["Imports"] = self.pyFilesImportsScan()
        
        return output

    def codeScan(self):
        output = {} 

        output["Files"] = self.pyFilesGeneralScan()
        
        return output

    def fullScan(self):
        output = {}

        output["Dependencies"] = self.dependencyScan()
        output["Code"] = self.codeScan()

        return output["Dependencies"]  , output["Code"]

    # ---------------------------------- AI Code Reviewer ----------------------------------

    def getAIVulnRecommendation(self, vulnData):
        
        # Load environment variables from .env file
        load_dotenv()

        # Retrieve the API key from environment variables
        api_key = os.getenv('OPENAI_API_KEY')

        # Check if API key is loaded properly
        if not api_key:
            raise Exception("API key not found. Please check your .env file.")

        # Create an instance of CodeReviewer
        reviewer = AICodeReviewer(api_key)

        # Review the code
        return(reviewer.getVulnRecommendation(vulnData))
    



                    
                
                



        


        
                









        
