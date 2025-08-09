import csv
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import smtplib
from email.message import EmailMessage

def generate_reports(found_credentials, target=None, protocol=None, total_attempts=None, output_dir="output"):
    if not found_credentials:
        print("[!] No credentials to report.")
        return None

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    csv_path = os.path.join(output_dir, f"report_{timestamp}.csv")
    pdf_path = os.path.join(output_dir, f"report_{timestamp}.pdf")

    # Build summary text
    summary_lines = [
        f"Brute Force Attack Report",
        f"Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Target: {target if target else 'N/A'}",
        f"Protocol: {protocol.upper() if protocol else 'N/A'}",
        f"Total Attempts: {total_attempts if total_attempts is not None else 'N/A'}",
        f"Successful Hits: {len(found_credentials)}",
        "-" * 40
    ]

    # CSV
    with open(csv_path, "w", newline="") as file:
        writer = csv.writer(file)
        # Write summary section in CSV
        for line in summary_lines:
            writer.writerow([line])
        writer.writerow([])  # blank line before data
        writer.writerow(["Username", "Password"])
        writer.writerows(found_credentials)
    print(f"[+] CSV report saved to {csv_path}")

    # PDF
    c = canvas.Canvas(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, 750, "Brute Force Attack Report")
    c.setFont("Helvetica", 11)
    y = 730
    for line in summary_lines[1:]:
        c.drawString(100, y, line)
        y -= 15
    y -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y, "Credentials Found:")
    y -= 20
    c.setFont("Helvetica", 11)
    for user, pwd in found_credentials:
        c.drawString(100, y, f"{user} : {pwd}")
        y -= 15
        if y < 50:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 11)
    c.save()
    print(f"[+] PDF report saved to {pdf_path}")

    return [csv_path, pdf_path]

def send_email_report(report_paths, smtp_config, log_callback):
    try:
        msg = EmailMessage()
        msg["Subject"] = "Brute Force Attack Report"
        msg["From"] = smtp_config["user"]
        msg["To"] = smtp_config["recipient"]
        msg.set_content("Attached are the brute force attack results with summary.")

        for path in report_paths:
            with open(path, "rb") as f:
                data = f.read()
                msg.add_attachment(
                    data,
                    maintype="application",
                    subtype="octet-stream",
                    filename=os.path.basename(path)
                )

        with smtplib.SMTP(smtp_config["server"], smtp_config["port"]) as server:
            server.starttls()
            server.login(smtp_config["user"], smtp_config["password"])
            server.send_message(msg)
        log_callback("[+] Report emailed successfully.")
    except Exception as e:
        log_callback(f"[!] Failed to send email: {e}")
