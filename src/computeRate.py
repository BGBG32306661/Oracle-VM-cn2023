from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *
from collections import Counter
import sys
import os

# get path of pcap file
INPUTDIR = sys.argv[1]
if INPUTDIR[-1] != '/':
    INPUTDIR += '/'
traffic = Counter()

dest_dict = ["3:7777", "3:7778", "4:7779"]
tcp_dict = {}
udp_dict = {}

def traffic_callback(packet):
    if IP in packet and hasattr(packet[IP], 'load') and packet[IP][0].proto in [6, 17]:
        packet = packet[IP]
        traffic.update({(packet.src[-1] + ":" + str(packet.sport), packet.dst[-1]+ ":" + str(packet.dport), packet[IP][0].proto): packet.len})

def get_pcap(dirname: str) -> list:
    pcap_paths = []
    files = os.listdir(dirname)
    for fname in files:
        if fname.split('.')[1] == 'pcap':
            pcap_paths.append(dirname + fname)
    return pcap_paths

def proc_pcap(pcap_paths: list) -> dict:
    ret_dict = {}
    for pcap in pcap_paths:
        packets = rdpcap(pcap)
        timediff = packets[-1].time - packets[0].time
        for p in packets:
            traffic_callback(p)

def display_traffic():
    BITS_IN_BYTE = 8
    MEGABIT = 1_000_000

    for key, val in sorted(traffic.items(), key=lambda item: item[0][2]):
        if key[1] not in dest_dict:
            continue

        if key[2] == 6:
            tcp_dict[key] = val
        else:
            udp_dict[key] = val

    print("--- TCP ---")
    for index, (key, val) in enumerate(tcp_dict.items()):
        throughput_mbps = (val * BITS_IN_BYTE) / MEGABIT
        print(f"Flow{index + 1}(h{key[0][0]}->h{key[1][0]}): {throughput_mbps:.2f} Mbps")

    print("--- UDP ---")
    for index, (key, val) in enumerate(udp_dict.items()):
        throughput_mbps = (val * BITS_IN_BYTE) / MEGABIT
        print(f"Flow{index + 1}(h{key[0][0]}->h{key[1][0]}): {throughput_mbps:.2f} Mbps")

if __name__ == "__main__":
    pcap_paths = get_pcap(INPUTDIR)
    proc_pcap(pcap_paths)
    display_traffic()

