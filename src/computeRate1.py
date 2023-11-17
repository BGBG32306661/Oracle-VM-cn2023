from scapy.config import conf
conf.disable_ipv6 = False
from scapy.all import *
from collections import Counter
import sys
import os

directory = sys.argv[1]
if not directory.endswith('/'):
    directory += '/'

traffic_counter = Counter()
target_ports = ["3:7777", "3:7778", "4:7779"]
tcp_traffic = {}
udp_traffic = {}

def analyze_packet(packet):
    if IP in packet and hasattr(packet[IP], 'load') and packet[IP][0].proto in [6, 17]:
        packet = packet[IP]
        traffic_counter.update({(packet.src[-1] + ":" + str(packet.sport), packet.dst[-1]+ ":" + str(packet.dport), packet[IP][0].proto): packet.len})

def get_pcap_files(dir_name: str) -> list:
    pcap_file_paths = []
    files = os.listdir(dir_name)
    for file_name in files:
        if file_name.split('.')[1] == 'pcap':
            pcap_file_paths.append(dir_name + file_name)
    return pcap_file_paths

def process_pcap_files(pcap_file_paths: list) -> dict:
    data_dict = {}
    for pcap_file in pcap_file_paths:
        packets = rdpcap(pcap_file)
        time_diff = packets[-1].time - packets[0].time
        for packet in packets:
            analyze_packet(packet)
    data_dict['traffic'] = traffic_counter
    return data_dict

def display_traffic_info():
    BITS_PER_BYTE = 8
    MEGABIT = 1_000_000

    for key, val in sorted(traffic_counter.items(), key=lambda item: item[0][2]):
        if key[1] not in target_ports:
            continue

        if key[2] == 6:
            tcp_traffic[key] = val
        else:
            udp_traffic[key] = val

    print("--- TCP ---")
    for index, (key, val) in enumerate(tcp_traffic.items()):
        throughput_mbps = (val * BITS_PER_BYTE) / MEGABIT
        print(f"Flow{index + 1}(h{key[0][0]}->h{key[1][0]}): {throughput_mbps:.2f} Mbps")

    print("--- UDP ---")
    for index, (key, val) in enumerate(udp_traffic.items()):
        throughput_mbps = (val * BITS_PER_BYTE) / MEGABIT
        print(f"Flow{index + 1}(h{key[0][0]}->h{key[1][0]}): {throughput_mbps:.2f} Mbps")

if __name__ == "__main__":
    pcap_files = get_pcap_files(directory)
    traffic_data = process_pcap_files(pcap_files)
    traffic_counter = traffic_data['traffic']
    display_traffic_info()

