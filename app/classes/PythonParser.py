# Used to parse the code and get the syntax tree
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
from pprint import pprint
from termcolor import colored
import json,re

# TODO: read from directory and identify all the python files and requements files

# Graphical User interface
# Probably flask-based web interface

# LIBRARIES 
# TODO: GUI


class PythonParser:
    def __init__(self, targetFile, targetReqFile=None, logging=False):
        self.language = Language(tspython.language(), "python")
        self.targetFile = targetFile
        self.tragetReqFile = targetReqFile
        self.parser = Parser()
        self.parser.set_language(self.language)
        self.sourceCode = None
        self.tree = None
        self.vulnDBFileName = 'db\\insecure.json'
        self.vulnDB = self.LoadDB(self.vulnDBFileName)
        self.fullVulnDBFileName = 'db\\insecure_full.json'
        self.fullVulnDB = self.LoadDB(self.fullVulnDBFileName)
        self.logging = logging

        print(colored("Target Python File: ", "green") + targetFile)
        print(colored("Target Requirements File: ", "green") + targetReqFile + "\n")

    def LoadDB(self, DBName):
        with open(DBName, 'r') as json_file:
            db = json.load(json_file)    
        return db
    
    def parseFile(self):
        with open(self.targetFile, "rb") as file:
            self.sourceCode = file.read()
        self.tree = self.parser.parse(self.sourceCode)

    def query(self, queryString):
        query = self.language.query(queryString)
        return query.captures(self.tree.root_node)

    def printCaptured(self, title, captured):
        print(colored(title, "red"))
        print(colored("Captured:", "green"), len(captured), "occurrences")
        for i in captured:
            # print(i[1], i[0].start_point, i[0].end_point, i[0].text)
            print(i[0].text.decode("utf-8"))
        print(colored("-----------------------------------------------------------------------","white"))

    def basicParse(self):
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
        return self.queryParse(queries)
    
    def advancedParse(self):
        queries = {
        "Imports": "(import_statement) @importStatement",
        "Imports Names": "(import_statement (dotted_name) @importName)",
        "Imports from": "(import_from_statement) @importFromStatement",
        "Imports from Names": "(import_from_statement module_name: (dotted_name) @importFromName)",
        "Imports Functions": "(import_from_statement name: (dotted_name) @importFromFunctions)",
        "Class Definitions": "(class_definition) @classDefinition",
        "Function Definitions": "(function_definition) @functionDefinition",
        "Function Names": "(function_definition name: (identifier) @functionName)",
        "Assignments": "(assignment) @assignment",
        "Strings": "(string) @string",
        "Comments": "(comment) @comment",
        }
        return self.queryParse(queries)
    
    def queryParse(self, queries):
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

    def requirementsParse(self, location):
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
            
    def checkVulnLibs(self):
        
        vulnLibs = {}
        # Define a regular expression pattern to match the operator and the value
        pattern = r'(==|[<>]=?)([0-9a-zA-Z.]+)'

        if self.logging:
            print(colored("Vulnerable Libraries Detected:", "red"))

        requirements = self.requirementsParse(self.tragetReqFile)
        
        LibsMissingVersion = []

        for RequiredLib in requirements:
            if RequiredLib in self.vulnDB:
                vulnLibVersions = self.vulnDB[RequiredLib]
                ReqLibVersion = requirements[RequiredLib]

                if ReqLibVersion is None:
                    LibsMissingVersion.append(RequiredLib)
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

    def advancedCheckVulnLibs(self):
        vulnLibs , _ = self.checkVulnLibs()
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
                    
    def checkVulnImports(self):
        query = {
            "Imports Names": "(import_statement (dotted_name) @importName)",
            "Imports from Names": "(import_from_statement module_name: (dotted_name) @importFromName)"
            }
        queryOutput = self.queryParse(query)

        imports = queryOutput["Imports Names"] + queryOutput["Imports from Names"]

        vulnLibs = {}

        for importedLib in imports:
            importedLib = importedLib.split(".")[0]

            if importedLib in self.vulnDB:
                # store name and versions in vulndb
                versions = self.vulnDB[importedLib]
                vulnLibs[importedLib] = versions

        return vulnLibs

 
                
            
                



        


        
                









        
