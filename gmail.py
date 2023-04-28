import ssl
import smtplib
from email.message import EmailMessage

# Email
email_sender = "hawk.solver@gmail.com"
email_pass = "aypxbzgtgbmzscjz"
email_receiver = "oleksandr.yastrebov.ca@gmail.com"
subject = "Report about your system"
body = """
Hello dear customer,

It is report that was sent automatically. It includes all open issues on your system with some advices.
Don't reply.

Thank you for using our product.
Hawk
"""
with open('report.txt', 'r') as file:
    temp = file.read()
body += temp
em = EmailMessage()
em['From'] = email_sender
em['To'] = email_receiver
em['Subject'] = subject
em.set_content(body)

context = ssl.create_default_context()

with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
    smtp.login(email_sender, email_pass)
    smtp.sendmail(email_sender, email_receiver, em.as_string())
