import json
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

#Configuring output in file
print("Script is running")
original = sys.stdout
path = 'report.txt'
sys.stdout = open(path, 'w')

# Variables
now = datetime.now()
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
protocols_dict = {
    "20": "You are using FTP protocol which is not secure.\n" + " "*32 +
          "You should use SFTP.",
    "22": "Be sure that you aren't using easy password\n" + " "*32 +
          "and default user for login via ssh",
    "23": "You are using Telnet protocol which is not secure.\n" + " "*32 +
          "You should use SSH",
    "25": "Without proper configuration and protection,\n" + " "*32 +
          "this TCP port is vulnerable to spoofing and spamming.",
    "53": "Protocol is particularly vulnerable to DDoS attacks",
    "69": "You are using FTP protocol which is not secure.\n" + " "*32 +
          "You should use SFTP",
    "80": "You are using HTTP which is allowed others\n" + " "*32 +
          "to deliver DDoS Attack or just visit\n" + " "*32 +
          "your webserver without authentication",
    "110": "This protocol sends all data as a plain text\n" + " "*32 +
           "Your password and login can being seen",
    "137": "Protocol is vulnerable to exploits",
    "143": "that it transmits logins from the client\n" + " "*32 +
           "to the server in plain text by default,\n" + " "*32 +
           "meaning usernames and passwords are not encrypted",
    "161": "You are using SNMP, SNMPv1 and SNMPv2 don't support,\n" + " "*32 +
           "encryption. Check If your version is 3",
    "443": "You are using HTTP which is allowed others\n" + " "*32 +
           " to deliver DDoS Attack or just visit\n" + " "*32 +
           " your webserver without authentication",
    "1433": "Quite often, attackers probe these ports\n" + " "*32 +
           "to find unprotected database with exploitable default configurations",
    "3389": "Be sure that you aren't using easy password\n" + " "*32 +
          "and default user for login via RDP",
}
protocols_dict["8080"] = protocols_dict["80"]
protocols_dict["139"] = protocols_dict["137"]
protocols_dict["8443"] = protocols_dict["443"]
protocols_dict["1434"], protocols_dict["3306"] = protocols_dict["1433"], protocols_dict["1433"]
def getIP(): # global ip
    d = str(urlopen('http://checkip.dyndns.com/').read())
    return r.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(d).group(1)

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)
global_ip = getIP()

os_version = platform.platform()

# Main Info
print("_" * 20, "Script was started ", str(now)[11:19], "_" * 20, sep="")
print("Hostname:".ljust(15), hostname)
print("Local IP:".ljust(15), local_ip)
print("Global IP:".ljust(15), global_ip)
print("OS:".ljust(15), os_version)

# Nmap3 requests
nmap = nmap3.Nmap()
os_results = nmap.nmap_os_detection(local_ip)
top_ports_results = nmap.scan_top_ports(local_ip, default=500, args="-sV")
list_results = nmap.nmap_list_scan(local_ip)

# Recording data in other files
with open("results_nmap3.log", "w") as write_file:
    json.dump(top_ports_results, write_file, indent=4, sort_keys=True)
with open("results_nmap3.log", "r") as read_file:
    data = json.load(read_file)
with open('open_ports.log', 'w', ) as output:
    print("date and time =", dt_string, file=output)

# Data processing and finding open ports. Feedback to user
print("\nService".ljust(15), "Port".ljust(6), "Status".ljust(9), "Info")
for protocol in data[local_ip]['ports']:
    if protocol['state'] == 'open' or protocol['state'] == 'filtered':
        print(protocol['service']['name'].ljust(14), protocol['portid'].ljust(6), protocol['state'].ljust(7), end="\t")
        if protocol['portid'] in protocols_dict.keys():
            print(protocols_dict[protocol['portid']])
        else:
            print("not critical")
        with open("open_ports.log", "a") as file:
            json.dump(protocol, file, indent=4, sort_keys=True)

# Ending of main info
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
    email_sender = "youremail" # needs to be configured as written in instruction
    email_pass = "google_uniq_pass_for_application"
    email_receiver = str(input("Please enter your email address correctly:"))
    email_receiver = email_correct(pattern, email_receiver)
    subject = "Report about your system"
    body = """
    Hello dear customer,

    It is report that was sent as you wished. It includes all open issues on your system with some advices.
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
print("Additional information you can find in the current directory")
input("Enter any key to quit")
sys.exit()
