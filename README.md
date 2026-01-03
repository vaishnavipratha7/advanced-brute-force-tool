# Advanced Brute Force Simulation Tool (GUI)

This is a small security-testing tool I built during my internship work.  
It provides a simple GUI to run **authorized** brute-force simulations against common services and export the results.

## What it can do
- GUI-based runner (easy to use, live logs)
- Supports: HTTP, FTP, SSH, SMTP
- Multi-threaded attempts (faster than single-thread)
- Optional HTTP crawling (collects URLs from the same domain)
- Generates CSV + PDF report
- Can email the report through SMTP (optional)
- Saves basic settings locally so you don’t retype everything every time

## What it is NOT
- Not meant for illegal use (only test systems you own or have permission for)
- Not a replacement for professional tools like Hydra/Medusa
- HTTP mode is a simple form POST approach (real websites may vary)

## How to run
1. Install dependencies:
   pip install -r requirements.txt

2. Start:
   python main.py

### Files
main.py – GUI + input validation + settings save/load

attacks.py – protocol handlers + multi-threaded worker queue

crawler.py – basic same-domain URL crawler (HTTP)

report_generator.py – CSV/PDF report + optional email sender

output/ – generated reports

wordlists/ – sample username/password lists

### for smtp
If you use Gmail for SMTP, you’ll need a Google App Password (normal password usually won’t work).

