import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re

class SQLInjectionScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection Scanner")
        self.root.geometry("550x400")
        self.root.configure(bg="#363636")

        self.title_label = tk.Label(root, text="SQL Injection Scanner", font=("Helvetica", 16, "bold"), bg="#363636", fg="orange")
        self.title_label.pack(pady=10)

        self.dir_frame = tk.Frame(root, bg="#363636")
        self.dir_frame.pack(pady=10)

        self.dir_label = tk.Label(self.dir_frame, text="Select Directory:", bg="#363636", fg="orange")
        self.dir_label.pack(side="left")

        self.dir_path = tk.StringVar()
        self.dir_entry = tk.Entry(self.dir_frame, textvariable=self.dir_path, width=30, bg="gray", fg="black")
        self.dir_entry.pack(side="left")

        self.browse_button = tk.Button(self.dir_frame, text="Browse", command=self.browse_directory, bg="#363636", fg="orange")
        self.browse_button.pack(side="left")

        self.scan_button = tk.Button(root, text="Scan", command=self.scan_directory, bg="#363636", fg="orange")
        self.scan_button.pack()

        self.results_text = scrolledtext.ScrolledText(root, width=60, height=15, bg="gray", fg="black") 
        self.results_text.pack()

    def browse_directory(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.dir_path.set(dir_path)

    def scan_directory(self):
        self.results_text.delete("1.0", tk.END)
        dir_path = self.dir_path.get()
        if not dir_path:
            messagebox.showerror("Error", "Please select a directory.")
            return

        vulnerabilities_found = False

        for root_dir, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root_dir, file)
                vulnerabilities = self.scan_file(file_path)
                if vulnerabilities:
                    vulnerabilities_found = True
                    self.results_text.insert(tk.END, f"Vulnerabilities detected in ")
                    self.results_text.insert(tk.END, file, 'filename')
                    self.results_text.insert(tk.END, f":\n")
                    for vulnerability, line_number in vulnerabilities:
                        self.results_text.insert(tk.END, f" - {vulnerability} at line {line_number}\n")
                    self.results_text.insert(tk.END, "\n")
                    
        if not vulnerabilities_found:
            self.results_text.insert(tk.END, "No SQL Injection vulnerabilities detected.")

        self.results_text.tag_configure('filename', background='red')

    def scan_file(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                code_lines = file.readlines()
                vulnerabilities = []

                # Patterns to detect vulnerabilities
                patterns = [
                    (r"(?:query\s*=\s*\".*?\".*?\+.*?\+\s*\".*?\")", "Escape Character Misuse Vulnerability"),
                    (r"(?:query\s*=\s*\".*?\".*?\%.*?\".*?\")", "Dynamic SQL Type Handling Vulnerability"),
                    (r"(SELECT|UPDATE|DELETE|INSERT)\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*'.*?'", "Direct Concatenation SQL Injection Vulnerability"),
                    (r"(\bexec\b\s+@\w+|\bexecute\b\s+@\w+)", "Exec/Execute Command Vulnerability"),
                    (r"(\bexec\b\s+@\w+\s+\bexec\b\s+\@\w+)", "Multiple Exec/Execute Command Vulnerability"),
                    (r"(SELECT\s+.+\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*\"\s*.+\s*\")", "String Based Injection Vulnerability"),
                    (r"(INSERT\s+INTO\s+\w+\s+\(.+\)\s+VALUES\s+\(.+\)\s*;?\s*)", "Insert Statement Injection Vulnerability"),
                    (r"(UPDATE\s+\w+\s+SET\s+\w+\s*=\s*'.+?'\s+WHERE\s+\w+\s*=\s*'.+?'\s*;?)", "Update Statement Injection Vulnerability"),
                    (r"(DELETE\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*'.+?'\s*;?)", "Delete Statement Injection Vulnerability"),
                    (r"(SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*LIKE\s*'.*?'\s*;?)", "LIKE Clause Injection Vulnerability"),
                    (r"(SELECT\s+.+\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*\d+)", "Numeric Based Injection Vulnerability"),
                    (r"(SELECT\s+.+\s+FROM\s+\w+\s+WHERE\s+\w+\s*IN\s*\(.+?\))", "IN Clause Injection Vulnerability")
                ]

                for line_number, line in enumerate(code_lines, start=1):
                    for pattern, vulnerability in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            vulnerabilities.append((vulnerability, line_number))
                    
                return vulnerabilities
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while scanning {file_path}: {str(e)}")

        return None

def main():
    root = tk.Tk()
    app = SQLInjectionScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()
