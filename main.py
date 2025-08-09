import os
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText
from attacks import BruteForceAttacker
import queue
import threading


class BruteForceTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Brute Force Simulation Tool")
        self.root.geometry("820x750")
        self.log_queue = queue.Queue()
        self.setup_gui()
        self.root.after(100, self.process_log_queue)  # periodic GUI log updates

    def setup_gui(self):
        # ---------- Target Settings ----------
        target_frame = ttk.Labelframe(self.root, text="Target Settings", padding=10)
        target_frame.pack(fill="x", pady=5, padx=10)
        ttk.Label(target_frame, text="Target URL / IP:").grid(row=0, column=0, sticky="w", pady=3)
        self.target_entry = ttk.Entry(target_frame, width=50)
        self.target_entry.grid(row=0, column=1, padx=5, pady=3)

        ttk.Label(target_frame, text="Protocol:").grid(row=1, column=0, sticky="w", pady=3)
        self.protocol = ttk.Combobox(target_frame, values=["http", "ftp", "ssh", "smtp"], width=12)
        self.protocol.grid(row=1, column=1, padx=5, pady=3, sticky="w")

        # ---------- Wordlists ----------
        wordlist_frame = ttk.Labelframe(self.root, text="Wordlists", padding=10)
        wordlist_frame.pack(fill="x", pady=5, padx=10)
        ttk.Label(wordlist_frame, text="Username Wordlist:").grid(row=0, column=0, sticky="w", pady=3)
        self.username_entry = ttk.Entry(wordlist_frame, width=50)
        self.username_entry.grid(row=0, column=1, padx=5, pady=3)
        ttk.Button(wordlist_frame, text="Browse", command=self.load_username_list).grid(row=0, column=2, padx=5)

        ttk.Label(wordlist_frame, text="Password Wordlist:").grid(row=1, column=0, sticky="w", pady=3)
        self.password_entry = ttk.Entry(wordlist_frame, width=50)
        self.password_entry.grid(row=1, column=1, padx=5, pady=3)
        ttk.Button(wordlist_frame, text="Browse", command=self.load_password_list).grid(row=1, column=2, padx=5)

        # ---------- Options ----------
        option_frame = ttk.Labelframe(self.root, text="Attack Options", padding=10)
        option_frame.pack(fill="x", pady=5, padx=10)
        self.crawl_var = ttk.BooleanVar()
        ttk.Checkbutton(option_frame, text="Crawl all pages (HTTP only)", variable=self.crawl_var).grid(row=0, column=0, sticky="w", columnspan=2)
        self.username_only_var = ttk.BooleanVar()
        user_only_cb = ttk.Checkbutton(option_frame, text="Username-only brute force (dummy password)", variable=self.username_only_var, command=self.toggle_password_field)
        user_only_cb.grid(row=1, column=0, sticky="w", columnspan=2)
        ttk.Label(option_frame, text="Attack Threads:").grid(row=2, column=0, sticky="w")
        self.thread_count = ttk.Spinbox(option_frame, from_=1, to=50, width=5)
        self.thread_count.set(10)
        self.thread_count.grid(row=2, column=1, sticky="w")

        # ---------- SMTP Settings ----------
        smtp_frame = ttk.Labelframe(self.root, text="SMTP Auto Mail Report (Optional)", padding=10)
        smtp_frame.pack(fill="x", pady=5, padx=10)
        ttk.Label(smtp_frame, text="Recipient Email:").grid(row=0, column=0, sticky="w")
        self.recipient_email = ttk.Entry(smtp_frame, width=50)
        self.recipient_email.grid(row=0, column=1)
        ttk.Label(smtp_frame, text="SMTP Server:").grid(row=1, column=0, sticky="w")
        self.smtp_server = ttk.Entry(smtp_frame, width=50)
        self.smtp_server.grid(row=1, column=1)
        ttk.Label(smtp_frame, text="SMTP Port:").grid(row=2, column=0, sticky="w")
        self.smtp_port = ttk.Entry(smtp_frame, width=10)
        self.smtp_port.insert(0, "587")
        self.smtp_port.grid(row=2, column=1, sticky="w")
        ttk.Label(smtp_frame, text="SMTP Username:").grid(row=3, column=0, sticky="w")
        self.smtp_user = ttk.Entry(smtp_frame, width=50)
        self.smtp_user.grid(row=3, column=1)
        ttk.Label(smtp_frame, text="SMTP Password:").grid(row=4, column=0, sticky="w")
        self.smtp_pass = ttk.Entry(smtp_frame, width=50, show='*')
        self.smtp_pass.grid(row=4, column=1)
        self.smtp_enable_var = ttk.BooleanVar()
        ttk.Checkbutton(smtp_frame, text="Send report via SMTP automatically", variable=self.smtp_enable_var).grid(row=5, column=0, columnspan=2, sticky="w")

        # ---------- Start ----------
        ttk.Button(self.root, text="Start Attack", bootstyle="danger", command=self.run_attack).pack(pady=10)

        # ---------- Logs ----------
        log_frame = ttk.Labelframe(self.root, text="Logs", padding=5)
        log_frame.pack(fill="both", expand=True, pady=5, padx=10)
        self.log_output = ScrolledText(log_frame, height=15)
        self.log_output.pack(fill="both", expand=True)

        # Initialize password field state
        self.toggle_password_field()

    def toggle_password_field(self):
        # Disable password wordlist entry if username-only mode is checked
        if self.username_only_var.get():
            self.password_entry.config(state="disabled")
        else:
            self.password_entry.config(state="normal")

    def load_username_list(self):
        path = filedialog.askopenfilename(title="Select Username Wordlist", filetypes=[["Text Files", "*.txt"]])
        if path:
            self.username_entry.delete(0, "end")
            self.username_entry.insert(0, path)

    def load_password_list(self):
        path = filedialog.askopenfilename(title="Select Password Wordlist", filetypes=[["Text Files", "*.txt"]])
        if path:
            self.password_entry.delete(0, "end")
            self.password_entry.insert(0, path)

    def log(self, message):
        self.log_queue.put(message)

    def process_log_queue(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get_nowait()
            self.log_output.insert("end", f"{msg}\n")
            self.log_output.see("end")
        self.root.after(100, self.process_log_queue)

    def normalize_url(self, url, protocol):
        url = url.strip()
        if protocol.lower() in ("http", "https"):
            if url.lower().startswith("http://"):
                url = url[7:]
            elif url.lower().startswith("https://"):
                url = url[8:]
            return protocol.lower() + "://" + url
        return url

    def run_attack(self):
        target = self.target_entry.get()
        protocol = self.protocol.get().lower()

        # Normalize URL
        target = self.normalize_url(target, protocol)

        username_wordlist = self.username_entry.get()
        password_wordlist = self.password_entry.get()
        crawl_enabled = self.crawl_var.get()
        username_only = self.username_only_var.get()

        try:
            threads = int(self.thread_count.get())
        except:
            threads = 10

        smtp_config = None
        if self.smtp_enable_var.get():
            smtp_config = {
                "recipient": self.recipient_email.get(),
                "server": self.smtp_server.get(),
                "port": int(self.smtp_port.get()),
                "user": self.smtp_user.get(),
                "password": self.smtp_pass.get()
            }

        if not all([target, protocol, username_wordlist]):
            self.log("[!] Please fill in Target, Protocol, and Username Wordlist before starting.")
            return

        try:
            with open(username_wordlist, 'r', encoding="utf-8", errors="ignore") as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log(f"[!] Failed to read username wordlist: {e}")
            return

        if username_only:
            passwords = ["password123"]
        else:
            if not password_wordlist:
                self.log("[!] Password wordlist is required unless username-only is enabled.")
                return
            try:
                with open(password_wordlist, 'r', encoding="utf-8", errors="ignore") as f:
                    passwords = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log(f"[!] Failed to read password wordlist: {e}")
                return

        def background_attack():
            attacker = BruteForceAttacker(
                protocol=protocol,
                target_url=target,
                usernames=usernames,
                passwords=passwords,
                log_callback=self.log,
                username_only=username_only,
                crawl_all=crawl_enabled if protocol == 'http' else False,
                threads=threads,
                smtp_config=smtp_config
            )
            attacker.attack()

        threading.Thread(target=background_attack, daemon=True).start()


if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = BruteForceTool(root)
    root.mainloop()
