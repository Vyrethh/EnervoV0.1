print(r"""


/========================================\
|| _____ _   _ _____ ______     _____   ||
||| ____| \ | | ____|  _ \ \   / / _ \  ||
|||  _| |  \| |  _| | |_) \ \ / / | | | ||
||| |___| |\  | |___|  _ < \ V /| |_| | ||
|||_____|_| \_|_____|_| \_\ \_/  \___/  ||
\========================================/

""")
print("                         Enervo")			 
print("         Network Recon & Port Scanner Toolkit v0.1")
print("                    Author: Vyreth")

start = input("Start Port Scan? Y/N: ")
if start.lower() != 'y':
    print("Exiting...")
    exit()

from scapy.all import *

ports = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]

def SynScan(host):
    ans, unans = sr(IP(dst=host)/TCP(sport=5555, dport=ports, flags="S"), timeout=2, verbose=0)
    print(f"Open ports at {host}:")
    for (s, r) in ans:
        if s[TCP].dport == r[TCP].sport:
            print(s[TCP].dport)

def DNSScan(host):
    ans, unans = sr(IP(dst=host)/UDP(sport=5555, dport=53)/DNS(rd=1, qd=DNSQR (qname = "google.com")), timeout=2, verbose=0)
    if ans:
        print(f"DNS Server at {host}")

host = "8.8.8.8"

SynScan(host)
DNSScan(host)
