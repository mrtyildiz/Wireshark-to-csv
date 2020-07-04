#!/usr/bin/python3
import pyshark
import os
import csv
def main():
    cap = pyshark.FileCapture('/home/murat/Desktop/ACCEPT_ICMP.pcapng', only_summaries=True, display_filter='icmp')
    cap_length = []
    for i in cap:
            cap_length.append(i)
    f = open('ACCEPT_ICMP.csv', 'w')

    with f:
        fnames = ['No', 'time', 'source_IP', 'destination_IP', 'Protocol', 'length', 'info']
        writer = csv.DictWriter(f, fieldnames=fnames)
        writer.writeheader()
        for i in range(len(cap_length)):
            ICMP = pyshark.FileCapture('/home/murat/Desktop/ACCEPT_ICMP.pcapng', only_summaries=True, display_filter='icmp')
            No = ICMP[i].no
            time = ICMP[i].time
            source_IP = ICMP[i].source
            destination_IP = ICMP[i].destination
            Protocol = ICMP[i].protocol
            length = ICMP[i].length
            info = ICMP[i].info
            writer.writerow({'No' : No, 'time': time, 'source_IP': source_IP, 'destination_IP': destination_IP, 'Protocol': Protocol, 'length': length, 'info': info})


if __name__=="__main__": 
    main() 
