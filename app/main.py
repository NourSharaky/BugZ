from classes.PythonParser import PythonParser


if __name__ == "__main__":
    
    # Read the code from a file
    targetFile = "..\\samples\\KH6051CEM_Practical_Cryptography_MyNoteTakingApp-main\\NoteTaking\\app.py"
    # Read the requirements from a file
    requirementsFile = "..\\samples\\KH6051CEM_Practical_Cryptography_MyNoteTakingApp-main\\requirements.txt"

    parser = PythonParser(targetFile, requirementsFile )
    parser.parseFile()
    parser.basicParse()

    parser.checkVulnLibs()

    



