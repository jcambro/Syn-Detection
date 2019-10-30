# FILE : detect.py
# DATE : 30 October 2019
# DEVELOPERS: R. Dekovich (dekovich@umich.edu)
#             J. Ambrose (jcambro@umich.edu)
# DESCRIPTION: Anomaly detection source code for P3


# REPRESENTS: command line arguments as input
import sys

# REPRESENTS: packet analysis and parsing
import dpkt

# REPRESENTS: conversion to IP format
import ipaddress


class PacketInfo:
    # CONSTRUCTOR: Takes in the TCP object and the IP object; sets frequency to 1 (new)
    def __init__(self, ip):
        self.ip_src = ip.src
        self.ip_dst = ip.dst
        self.freq = int(1)

    # Increments the frequency of the packet; has been instantiated before
    def inc_freq(self):
        self.freq += 1


def find_packet(ip, existing_packets):
    # Loop over every packet in the existing_packets array
    for idx, packet in enumerate(existing_packets):
        # Compare the IP sources; if the IP's match
        if ip.src == packet.ip_src:
            # Return the index of existing_packet where it is at
            return idx

    # Not found
    return -1

def find_packet_syn_ack(ip, existing_packets):
    # Loop over every packet in the existing_packets array
    for idx, packet in enumerate(existing_packets):
        # Compare the IP sources; if the IP's match
        if ip.dst == packet.ip_dst:
            # Return the index of existing_packet where it is at
            return idx

    # Not found
    return -1


# REQUIRES: file is a file_obj containing the pcap data,
#           found_packets is a list of PacketInfo,
#           find_syn is a boolean value representing if it is to find SYN packets only,
#           find_syn_ack is a boolean value representing if it is to find SYN+ACK packets only
# MODIFIES: found_syn
# EFFECTS: Finds all the packets specified, and increases their frequencies as needed be
def extract_all_packets(file, found_packets_syn, found_packets_syn_ack):
    # Open the pcap data into a Reader object
    pcap = dpkt.pcap.Reader(file)

    # Loop over each element in the pcap buffer..
    for timestamp, buffer in pcap:
        try:
            # Parse the buffer into a Ethernet object (contains IP, TCP..)
            eth = dpkt.ethernet.Ethernet(buffer)
        except dpkt.dpkt.NeedData:
            continue

        try:
            # Extract the IP and TCP data into their own objects
            ip = eth.data
            tcp = ip.data
        except AttributeError:
            continue

        # If the packet is not a valid Ethernet packet..
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            # Skip over this iteration
            continue

        # If the packet is not a valid TCP packet..
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            # Skip over this iteration
            continue

        # If only the SYN bit was specified (and not the ACK)..
        if (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
            # Search for the index in the existing list of packets..
            idx = find_packet(ip, found_packets_syn)

            # If the packet has been found before..
            if idx != -1:
                # Increment the frequency of appearance for that packet
                found_packets_syn[idx].inc_freq()
            else:
                # Append a new packet instance to the found_packets array
                found_packets_syn.append(PacketInfo(ip))

        # If the SYN bit was specified, and also the ACK..
        if (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK):
            # Search for the index in the existing list of packets..
            idx = find_packet_syn_ack(ip, found_packets_syn_ack)

            # If the packet has been found before..
            if idx != -1:
                # Increment the frequency of appearance for that packet
                found_packets_syn_ack[idx].inc_freq()
            else:
                # Append a new packet instance to the found_packets array
                found_packets_syn_ack.append(PacketInfo(ip))


def print_sniff_packets(syn_packets, syn_ack_packets):
    # Loop through each element of the SYN packets
    for packet in syn_packets:
        # For each element that is SYN+ACK
        found = False
        for syn_ack in syn_ack_packets:
            # If the src of SYN is the same as dest of SYN+ACK
            if packet.ip_src == syn_ack.ip_dst:
                found = True
                freq_threshold = syn_ack.freq * 3
                if packet.freq >= freq_threshold:
                    print(ipaddress.IPv4Address(packet.ip_src))
                break

        if not found:
            # There were no SYN ACKS sent back.
            print(ipaddress.IPv4Address(packet.ip_src))


def main():
    # Acquire the filename from the command line arguments
    filename = sys.argv[1]

    # Create an array of PacketInfo to contain the SYN packets found
    found_syn_packets = []

    # Create an array of PacketInfo to contain the SYN+ACK packets found
    found_syn_ack_packets = []

    # Open the pcap file up as a binary buffer
    with open(filename, "rb") as file:
        # Extract all the SYN packets from the pcap buffer
        extract_all_packets(file, found_syn_packets, found_syn_ack_packets)

    print_sniff_packets(found_syn_packets, found_syn_ack_packets)

    exit(0)

if __name__ == "__main__":
    main()
