# Used to parse the code and get the syntax tree
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
from pprint import pprint
from termcolor import colored
import json,re

# TODO: read from directory and identify all the python files and requements files

# LIBRARIES 
# TODO: Insecure Full List
# TODO: python file imports


class PythonParser:
    def __init__(self, targetFile, targetReqFile=None):
        self.language = Language(tspython.language(), "python")
        self.targetFile = targetFile
        self.tragetReqFile = targetReqFile
        self.parser = Parser()
        self.parser.set_language(self.language)
        self.sourceCode = None
        self.tree = None
        self.vulnDBFileName = 'db\\insecure.json'
        self.vulnDB = self.LoadVulnDB()

    def LoadVulnDB(self):
        with open(self.vulnDBFileName, 'r') as json_file:
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
            "Imports": "(import_from_statement) @importFromStatement",
            "Class Definitions": "(class_definition) @classDefinition",
            "Function Definitions": "(function_definition) @functionDefinition",
            "Function Names": "(function_definition name: (identifier) @functionName)",
            "Assignments": "(assignment) @assignment",
            "Strings": "(string) @string",
            "Comments": "(comment) @comment",
        }
        for title, query in queries.items():
            captured = self.query(query)
            self.printCaptured(title, captured)

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
                    # print(RequiredLib,"-",ReqLibVersion,"-",conditions)
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
                    vulnLibs[RequiredLib] = requirements[RequiredLib]
                    print(RequiredLib, ReqLibVersion, "is vulnerable to attacks", conditions)

        print(colored("Libraries Missing Version:", "red"))
        print(LibsMissingVersion)

        return vulnLibs 
                        
        
                









        
