import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, Toplevel, CENTER
from tkinter.scrolledtext import ScrolledText

class BruteForceTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Brute Force Simulation Tool")
        self.root.geometry("700x600")
        
        self.setup_gui()

    def setup_gui(self):
        # Target URL/IP
        ttk.Label(self.root, text="Target URL / IP:").pack(pady=5)
        self.target_entry = ttk.Entry(self.root, width=50)
        self.target_entry.pack()

        # Username input
        ttk.Label(self.root, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self.root, width=50)
        self.username_entry.pack()

        # Wordlist
        ttk.Label(self.root, text="Password Wordlist:").pack(pady=5)
        self.wordlist_path = ttk.Entry(self.root, width=50)
        self.wordlist_path.pack()
        ttk.Button(self.root, text="Browse", command=self.load_wordlist).pack()

        # Protocol Selection
        ttk.Label(self.root, text="Select Protocol:").pack(pady=5)
        self.protocol = ttk.Combobox(self.root, values=["http", "ftp", "ssh", "smtp"])
        self.protocol.pack()

        # Start button
        ttk.Button(self.root, text="Start Attack", bootstyle="danger", command=self.run_attack).pack(pady=10)

        # Log window
        ttk.Label(self.root, text="Logs:").pack()
        self.log_output = ScrolledText(self.root, height=15)
        self.log_output.pack(padx=10, pady=10, fill='both', expand=True)

    def load_wordlist(self):
        path = filedialog.askopenfilename(title="Select Password Wordlist")
        self.wordlist_path.delete(0, "end")
        self.wordlist_path.insert(0, path)

    def log(self, message):
        self.log_output.insert("end", f"{message}\n")
        self.log_output.see("end")

    def run_attack(self):
        target = self.target_entry.get()
        username = self.username_entry.get()
        wordlist = self.wordlist_path.get()
        protocol = self.protocol.get()
        self.log(f"[+] Simulating attack on {protocol.upper()} at {target} using {username}... (wordlist: {wordlist})")
        # We'll add real attack logic next

if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = BruteForceTool(root)
    root.mainloop()
