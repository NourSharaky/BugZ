import bandit.blacklists.calls
from classes.PythonParser import PythonParser
from classes.AICodeReviewer import AICodeReviewer
from termcolor import colored
from pprint import pprint
import bandit 
import openai
from dotenv import load_dotenv
import os

if __name__ == "__main__":

    # x = bandit.blacklists.calls.gen_blacklist().items().__iter__().__next__()
    # pprint(x)

    print(colored("BugZ Initialized", "magenta"))

    # --------------------------- Python Parser ---------------------------
    projectFolder = "D:\\TKH\\BugZ\\samples\\KH6051CEM_Practical_Cryptography_MyNoteTakingApp-main"
    # projectFolder = "D:\\TKH\\BugZ\\samples\\vulpy-master"
    parser = PythonParser(logging=False, projectFolder=projectFolder)
      
    # --------------------------- Vulnerability Scanning ---------------------------

    # print(colored("Dependency Scan: ", "red"))
    # print(parser.dependencyScan())

    print(colored("Code Scan: ", "red"))
    print(parser.codeScan())









