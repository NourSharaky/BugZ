import bandit.blacklists.calls
from classes.PythonParser import PythonParser
from termcolor import colored
from pprint import pprint
import bandit 

if __name__ == "__main__":

    # x = bandit.blacklists.calls.gen_blacklist().items().__iter__().__next__()
    # pprint(x)

    print(colored("BugZ Initialized", "magenta"))

    projectFolder = "D:\\TKH\\BugZ\\samples\\KH6051CEM_Practical_Cryptography_MyNoteTakingApp-main"
    parser = PythonParser(logging=False, projectFolder=projectFolder)
    

    pythonFiles , requirementsFile = parser.scanDirectory()


    print(colored("Vulnerable Libraries in requirements: ", "red"))
    requirementsFileVulnFullScan =  parser.requirementsFileVulnFullScan()
    print(requirementsFileVulnFullScan)

    # print(colored("Vulnerable Imports in files: ", "red"))
    # pprint(parser.pyFilesImportsScan())

    print("----------------------------------------------------------------------------------------")

    print(colored("Vulnerablities in files: ", "red"))
    print(parser.pyFilesGeneralScan())
    








