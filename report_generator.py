import csv
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import smtplib
from email.message import EmailMessage


def generate_reports(found_credentials, target=None, protocol=None, total_attempts=None, output_dir="output"):
    # Always generate a report (even if 0 hits)
    if found_credentials is None:
        found_credentials = []

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    csv_path = os.path.join(output_dir, f"report_{timestamp}.csv")
    pdf_path = os.path.join(output_dir, f"report_{timestamp}.pdf")

    summary_lines = [
        "Brute Force Attack Report",
        f"Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Target: {target if target else 'N/A'}",
        f"Protocol: {protocol.upper() if protocol else 'N/A'}",
        f"Total Attempts: {total_attempts if total_attempts is not None else 'N/A'}",
        f"Successful Hits: {len(found_credentials)}",
        "-" * 40
    ]

    # CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        for line in summary_lines:
            writer.writerow([line])
        writer.writerow([])
        writer.writerow(["Username", "Password"])
        if found_credentials:
            writer.writerows(found_credentials)
        else:
            writer.writerow(["(none)", "(none)"])

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
    if found_credentials:
        for user, pwd in found_credentials:
            c.drawString(100, y, f"{user} : {pwd}")
            y -= 15
            if y < 50:
                c.showPage()
                y = 750
                c.setFont("Helvetica", 11)
    else:
        c.drawString(100, y, "No valid credentials found.")
        y -= 15

    c.save()
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
