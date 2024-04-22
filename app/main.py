from classes.PythonParser import PythonParser
from termcolor import colored
from pprint import pprint

if __name__ == "__main__":

    print(colored("BugZ Initialized", "magenta"))

    # Read the code from a file
    targetFile = "..\\samples\\KH6051CEM_Practical_Cryptography_MyNoteTakingApp-main\\NoteTaking\\app.py"
    # Read the requirements from a file
    # requirementsFile = "..\\samples\\KH6051CEM_Practical_Cryptography_MyNoteTakingApp-main\\requirements.txt"

    projectFolder = "D:\\TKH\\BugZ\\samples\\KH6051CEM_Practical_Cryptography_MyNoteTakingApp-main"
    parser = PythonParser(logging=False, projectFolder=projectFolder)
    # parser.parseFile()
    # parser.basicParse()

    pythonFiles , requirementsFile = parser.scanDirectory()

    # vulnLibs, LibsMissingVersion = parser.checkVulnLibs()

    # print(colored("Vulnerable Libraries: ", "red"))
    # pprint(vulnLibs)

    # print(colored("Libraries Missing Version: ", "yellow"))
    # pprint(LibsMissingVersion)

    # print(colored("Vulnerable Imports: ", "red"))
    # vulnImports = parser.checkVulnImports()
    # pprint(vulnImports)

    # print(colored("Advanced Vulnerable Libraries: ", "red"))
    # advancedVulnLibs =  parser.advancedCheckVulnLibs()
    # pprint(advancedVulnLibs)

    pprint(parser.scanPythonFiles())

    



