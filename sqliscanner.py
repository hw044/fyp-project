import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re

class SQLInjectionScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection Scanner")
        self.root.geometry("550x300")
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

        self.results_text = scrolledtext.ScrolledText(root, width=60, height=10, bg="gray", fg="black") 
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
                    self.results_text.insert(tk.END, f" - {', '.join(vulnerabilities)}\n\n")
                    
        if not vulnerabilities_found:
            self.results_text.insert(tk.END, "No SQL Injection vulnerabilities detected.")

        self.results_text.tag_configure('filename', background='red')

    def scan_file(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                code = file.read()
                vulnerabilities = []

                # Pattern to detect improper escaping of special characters
                ESCAPE_CHAR_VULNERABILITY_PATTERN = r"(?:query\s*=\s*\".*?\".*?\+.*?\+\s*\".*?\")"
                if re.search(ESCAPE_CHAR_VULNERABILITY_PATTERN, code, re.IGNORECASE):
                    vulnerabilities.append("Escape Character Misuse Vulnerability")

                # Pattern to detect improper handling of dynamic SQL types
                DYNAMIC_SQL_TYPE_VULNERABILITY_PATTERN = r"(?:query\s*=\s*\".*?\".*?\%.*?\".*?\")"
                if re.search(DYNAMIC_SQL_TYPE_VULNERABILITY_PATTERN, code, re.IGNORECASE):
                    vulnerabilities.append("Dynamic SQL Type Handling Vulnerability")

                # Pattern to detect basic SQL injection vulnerability via direct concatenation
                SQL_INJECTION_DIRECT_CONCAT_PATTERN = r"(SELECT|UPDATE|DELETE|INSERT)\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*'.*?'"
                if re.search(SQL_INJECTION_DIRECT_CONCAT_PATTERN, code, re.IGNORECASE):
                    vulnerabilities.append("Direct Concatenation SQL Injection Vulnerability")
                    
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
