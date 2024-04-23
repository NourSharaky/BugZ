import tkinter as tk
from tkinter import filedialog

def select_directory():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    directory = filedialog.askdirectory()  # Show the directory selection dialog
    root.destroy()  # Ensure the root is destroyed after selection
    return directory

if __name__ == "__main__":
    selected_dir = select_directory()
    print(selected_dir)  # Print the selected directory path to stdout
