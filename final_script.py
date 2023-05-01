import json
import os
import platform
import re as r
import socket
import nmap3
from datetime import datetime
from urllib.request import urlopen
import sys
import ssl
import smtplib
from email.message import EmailMessage
import re

#Writing output in file
print("Script is running")
original = sys.stdout
path = 'report.txt'
sys.stdout = open(path, 'w')

# Time
now = datetime.now()
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

# Variables
protocols_dict = {
    "20": "You are using FTP protocol which is not secure."
          " You should use SFTP.",
    "23": "You are using Telnet protocol which is not secure."
          " You should use SSH",
    "69": "You are using FTP protocol which is not secure."
          " You should use SFTP",
    "80": "You are using HTTP which is allowed others"
          " to deliver DDoS Attack or just visit your webserver without authentication ",
    "161": "You are using SNMP which is allowed others to try login and control your system",
    "443": "You are using HTTP which is allowed others"
           " to deliver DDoS Attack or just visit your webserver without authentication "
}
def getIP(): # global ip
    d = str(urlopen('http://checkip.dyndns.com/').read())
    return r.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(d).group(1)

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)
global_ip = getIP()

os_version = platform.platform()
"""if "Windows" in os_version:
    operation = 0
elif "Linux" in os_version:
    operation = 1
"""

# Writing in the console
print("_" * 20, "Script was started ", str(now)[11:19], "_" * 20, sep="")
print("Hostname:\t", hostname)
print("Local IP:\t", local_ip)
print("Global IP:\t", global_ip)
print("OS:\t\t", os_version)

# Nmap3
nmap = nmap3.Nmap()
os_results = nmap.nmap_os_detection(local_ip)
top_ports_results = nmap.scan_top_ports(local_ip, args="-sV")
list_results = nmap.nmap_list_scan(local_ip)

# Writing in the json format general data
with open("results_nmap3.log", "w") as write_file:
    json.dump(top_ports_results, write_file, indent=4, sort_keys=True)
with open("results_nmap3.log", "r") as read_file:
    data = json.load(read_file)
with open('open_ports.log', 'w', ) as output:
    print("date and time =", dt_string, file=output)

# Data processing and finding open ports. Feedback to user
print("\nService\t\t", "Port\t", "Status\t", "Info")
for protocol in data[local_ip]['ports']:
    if protocol['state'] == 'open':
        print(protocol['service']['name'], "\t", protocol['portid'], "\t", protocol['state'], end="\t")
        if protocol['portid'] in protocols_dict.keys():
            print(protocols_dict[protocol['portid']])
        else:
            print(protocol['portid'], "is opened, but not critical protocol")
        with open("open_ports.log", "a") as file:
            json.dump(protocol, file, indent=4, sort_keys=True)

# Conclusions
print("_" * 20, "Script was finished ", str(datetime.now())[11:19], "_" * 20, sep="")
sys.stdout.close()
sys.stdout = original

# Validation of email
pattern = r"^[-\w\.]+@([-\w]+\.)+[-\w]{2,4}$"

def email_correct(example, email):
    if re.match(example, email) is not None:
        print("Email is correct!")
        return email
    else:
        print("Wrong!")
        email = str(input("Please enter your email address correctly:"))
        return email_correct(example, email)


# Email sending
choice = str(input("Script was finished, do you want to see your report on the specific email or python CLI?\nemail or cli:"))
if choice.lower() == "email":
    email_sender = "your email"
    email_pass = "password created by google permission for specific application"
    email_receiver = str(input("Please enter your email address correctly:"))
    email_receiver = email_correct(pattern, email_receiver)
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
        print("Report was sent successfully")

elif choice.lower() == "cli":
    with open('report.txt', 'r') as file:
        print(file.read())
else:
    print("Command isn't correct")

#Exit
input("Enter any key to quit")
sys.exit()
