import os
import json
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText
from attacks import BruteForceAttacker
import queue
import threading


SETTINGS_FILE = "config.json"

DEFAULT_SETTINGS = {
    "target": "",
    "protocol": "http",
    "username_wordlist": "",
    "password_wordlist": "",
    "crawl_all": False,
    "username_only": False,
    "threads": 10,
    "smtp_enabled": False,
    "recipient": "",
    "smtp_server": "",
    "smtp_port": "587",
    "smtp_user": ""
}


class BruteForceTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Brute Force Simulation Tool")
        self.root.geometry("820x750")
        self.log_queue = queue.Queue()

        self.setup_gui()
        self.root.after(100, self.process_log_queue)  # periodic GUI log updates

        # Load saved settings (if any)
        self.load_settings_into_gui()

    # -------------------- Settings helpers --------------------
    def read_settings_file(self):
        if not os.path.exists(SETTINGS_FILE):
            return DEFAULT_SETTINGS.copy()

        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            merged = DEFAULT_SETTINGS.copy()
            merged.update({k: data.get(k, merged[k]) for k in merged.keys()})
            return merged
        except Exception as e:
            self.log(f"[!] Could not read {SETTINGS_FILE}: {e}")
            return DEFAULT_SETTINGS.copy()

    def write_settings_file(self, settings):
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)
            self.log(f"[+] Settings saved to {SETTINGS_FILE}")
        except Exception as e:
            self.log(f"[!] Failed to save settings: {e}")

    def collect_settings_from_gui(self):
        return {
            "target": self.target_entry.get().strip(),
            "protocol": (self.protocol.get() or "").strip().lower(),
            "username_wordlist": self.username_entry.get().strip(),
            "password_wordlist": self.password_entry.get().strip(),
            "crawl_all": bool(self.crawl_var.get()),
            "username_only": bool(self.username_only_var.get()),
            "threads": int(self.thread_count.get()) if str(self.thread_count.get()).isdigit() else 10,
            "smtp_enabled": bool(self.smtp_enable_var.get()),
            "recipient": self.recipient_email.get().strip(),
            "smtp_server": self.smtp_server.get().strip(),
            "smtp_port": self.smtp_port.get().strip(),
            "smtp_user": self.smtp_user.get().strip()
        }

    def apply_settings_to_gui(self, s):
        # Target + protocol
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, s.get("target", ""))

        proto = s.get("protocol", "http").lower()
        if proto not in ("http", "ftp", "ssh", "smtp"):
            proto = "http"
        self.protocol.set(proto)

        # Wordlists
        self.username_entry.delete(0, "end")
        self.username_entry.insert(0, s.get("username_wordlist", ""))

        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, s.get("password_wordlist", ""))

        # Options
        self.crawl_var.set(bool(s.get("crawl_all", False)))
        self.username_only_var.set(bool(s.get("username_only", False)))
        self.thread_count.set(str(s.get("threads", 10)))

        # SMTP
        self.smtp_enable_var.set(bool(s.get("smtp_enabled", False)))

        self.recipient_email.configure(state="normal")
        self.smtp_server.configure(state="normal")
        self.smtp_port.configure(state="normal")
        self.smtp_user.configure(state="normal")
        self.smtp_pass.configure(state="normal")

        self.recipient_email.delete(0, "end")
        self.recipient_email.insert(0, s.get("recipient", ""))

        self.smtp_server.delete(0, "end")
        self.smtp_server.insert(0, s.get("smtp_server", ""))

        self.smtp_port.delete(0, "end")
        self.smtp_port.insert(0, s.get("smtp_port", "587"))

        self.smtp_user.delete(0, "end")
        self.smtp_user.insert(0, s.get("smtp_user", ""))

        # Keep password blank in saved settings for safety (user types each time)
        self.smtp_pass.delete(0, "end")

        # Re-apply UI enable/disable logic
        self.toggle_password_field()
        self.update_gui_state()
        self.on_smtp_toggle()

    def save_settings_from_gui(self):
        settings = self.collect_settings_from_gui()
        # Do NOT save SMTP password
        self.write_settings_file(settings)

    def load_settings_into_gui(self):
        settings = self.read_settings_file()
        self.apply_settings_to_gui(settings)
        self.log("[+] Loaded settings.")

    # -------------------- GUI --------------------
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
        self.protocol.bind("<<ComboboxSelected>>", self.on_protocol_change)
        self.protocol.set("http")

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
        self.crawl_check = ttk.Checkbutton(
            option_frame,
            text="Crawl all pages (HTTP only)",
            variable=self.crawl_var
        )
        self.crawl_check.grid(row=0, column=0, sticky="w", columnspan=2)

        self.username_only_var = ttk.BooleanVar()
        user_only_cb = ttk.Checkbutton(
            option_frame,
            text="Username-only brute force (dummy password)",
            variable=self.username_only_var,
            command=self.toggle_password_field
        )
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
        self.smtp_check = ttk.Checkbutton(
            smtp_frame,
            text="Send report via SMTP automatically",
            variable=self.smtp_enable_var,
            command=self.on_smtp_toggle
        )
        self.smtp_check.grid(row=5, column=0, columnspan=2, sticky="w")

        # ---------- Action Buttons ----------
        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill="x", pady=10, padx=10)

        ttk.Button(button_frame, text="Start Attack", bootstyle="danger", command=self.run_attack).pack(side="left")
        ttk.Button(button_frame, text="Save Settings", bootstyle="secondary", command=self.save_settings_from_gui).pack(side="left", padx=10)
        ttk.Button(button_frame, text="Load Settings", bootstyle="secondary", command=self.load_settings_into_gui).pack(side="left")
        ttk.Button(button_frame, text="Clear Logs", bootstyle="secondary", command=self.clear_logs).pack(side="right")

        # ---------- Logs ----------
        log_frame = ttk.Labelframe(self.root, text="Logs", padding=5)
        log_frame.pack(fill="both", expand=True, pady=5, padx=10)

        self.log_output = ScrolledText(log_frame, height=15)
        self.log_output.pack(fill="both", expand=True)

        # Initialize state
        self.toggle_password_field()
        self.update_gui_state()
        self.on_smtp_toggle()

    def clear_logs(self):
        self.log_output.delete("1.0", "end")

    def on_protocol_change(self, event=None):
        self.update_gui_state()

    def update_gui_state(self):
        proto = (self.protocol.get() or "").lower()

        # Crawl only valid for HTTP
        if proto != "http":
            self.crawl_var.set(False)
            self.crawl_check.configure(state="disabled")
        else:
            self.crawl_check.configure(state="normal")

    def on_smtp_toggle(self):
        smtp_state = "normal" if self.smtp_enable_var.get() else "disabled"
        for field in [self.recipient_email, self.smtp_server, self.smtp_port, self.smtp_user, self.smtp_pass]:
            field.configure(state=smtp_state)

    def toggle_password_field(self):
        if self.username_only_var.get():
            self.password_entry.config(state="disabled")
        else:
            self.password_entry.config(state="normal")

    def load_username_list(self):
        path = filedialog.askopenfilename(
            title="Select Username Wordlist",
            filetypes=[["Text Files", "*.txt"]]
        )
        if path:
            self.username_entry.delete(0, "end")
            self.username_entry.insert(0, path)

    def load_password_list(self):
        path = filedialog.askopenfilename(
            title="Select Password Wordlist",
            filetypes=[["Text Files", "*.txt"]]
        )
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
        target = self.target_entry.get().strip()
        proto_raw = self.protocol.get()
        protocol = proto_raw.lower() if proto_raw else ""

        if target and protocol:
            target = self.normalize_url(target, protocol)

        username_wordlist = self.username_entry.get().strip()
        password_wordlist = self.password_entry.get().strip()
        crawl_enabled = self.crawl_var.get()
        username_only = self.username_only_var.get()

        # Validation
        if not target:
            self.log("[!] Please enter a Target URL/IP.")
            return
        if not protocol:
            self.log("[!] Please select a Protocol.")
            return
        if not username_wordlist:
            self.log("[!] Please select a Username wordlist file.")
            return
        if not os.path.exists(username_wordlist):
            self.log(f"[!] Username wordlist not found: {username_wordlist}")
            return

        if not username_only:
            if not password_wordlist:
                self.log("[!] Password wordlist is required unless username-only is enabled.")
                return
            if not os.path.exists(password_wordlist):
                self.log(f"[!] Password wordlist not found: {password_wordlist}")
                return

        # Threads
        try:
            threads = int(self.thread_count.get())
        except Exception:
            threads = 10
            self.log("[*] Invalid thread value, defaulting to 10.")

        # SMTP config
        smtp_config = None
        if self.smtp_enable_var.get():
            recipient = self.recipient_email.get().strip()
            server = self.smtp_server.get().strip()
            user = self.smtp_user.get().strip()
            password = self.smtp_pass.get()

            if not recipient:
                self.log("[!] SMTP enabled, but recipient email is empty.")
                return
            if not server:
                self.log("[!] SMTP enabled, but SMTP server is empty.")
                return
            if not user:
                self.log("[!] SMTP enabled, but SMTP username is empty.")
                return
            if not password:
                self.log("[!] SMTP enabled, but SMTP password is empty.")
                return

            try:
                port = int(self.smtp_port.get())
            except Exception:
                self.log("[!] Invalid SMTP port.")
                return

            smtp_config = {
                "recipient": recipient,
                "server": server,
                "port": port,
                "user": user,
                "password": password
            }

        # Load usernames
        try:
            with open(username_wordlist, 'r', encoding="utf-8", errors="ignore") as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log(f"[!] Failed to read username wordlist: {e}")
            return

        # Load passwords
        if username_only:
            passwords = ["password123"]
        else:
            try:
                with open(password_wordlist, 'r', encoding="utf-8", errors="ignore") as f:
                    passwords = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log(f"[!] Failed to read password wordlist: {e}")
                return

        # Save current settings (without SMTP password)
        self.save_settings_from_gui()

        self.log(f"[+] Ready. Users: {len(usernames)}, Passwords: {len(passwords)}, Threads: {threads}")

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
