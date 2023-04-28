import json
import os
import platform
import re as r
import socket
import nmap3
from datetime import datetime
from urllib.request import urlopen
import sys


#Writing output in file
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
# global_ip = getIP()

os_version = platform.platform()
if "Windows" in os_version:
    operation = 0
elif "Linux" in os_version:
    operation = 1


# Writing in the console
print("_" * 20, "Script was started ", str(now)[9:19], "_" * 20, sep="")
print("Hostname:\t", hostname)
print("Local IP:\t", local_ip)
# print("Global IP:\t", global_ip)
print("OS:\t\t\t", os_version)


# Nmap3
nmap = nmap3.Nmap()
os_results = nmap.nmap_os_detection(local_ip)
top_ports_results = nmap.scan_top_ports(local_ip, args="-sV")
subnet_results = nmap.nmap_subnet_scan(local_ip)
list_results = nmap.nmap_list_scan(local_ip)

# Writing in the json format general data
with open("results_nmap3.log", "w") as write_file:
    json.dump(top_ports_results, write_file, indent=4, sort_keys=True)
with open("results_nmap3.log", "r") as read_file:
    data = json.load(read_file)
with open('open_ports.log', 'w', ) as output:
    print("date and time =", dt_string, file=output)
with open("subnet.log", "w") as write_file:
    json.dump(subnet_results, write_file, indent=4, sort_keys=True)

# Functions
def solution(choice):
    if choice == 'c':
        print("okay")

# Data processing and finding open ports. Feedback to user
print("\nService\t\t\t", "Port\t", "Status\t\t", "Info")
for protocol in data[local_ip]['ports']:
    if protocol['state'] == 'open':
        print(protocol['service']['name'], "\t", protocol['portid'], "\t", protocol['state'], end="\t\t")
        if protocol['portid'] in protocols_dict.keys():
            print(protocols_dict[protocol['portid']])
        else:
            print(protocol['portid'], "is opened, but not critical protocol")
        with open("open_ports.log", "a") as file:
            json.dump(protocol, file, indent=4, sort_keys=True)

# Conclusions
print("_" * 20, "Script was finished ", str(datetime.now())[9:19], "_" * 20, sep="")
sys.stdout.close()
sys.stdout = open(original, 'w')
# Email sending
choice = str(input("Script was finished, do you want to get report on your email?\n yes or no:"))
if choice.lower() == "yes":
    os.system('python gmail.py')
else:
    with open('report.txt', 'r') as file:
        print(file.read())
