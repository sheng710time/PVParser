#!/usr/bin/env python3
"""
IP-based EtherNet/IP Packet Filtering Module

This module provides functions to filter EtherNet/IP packets based on IP addresses:
- Single IP filtering (packets involving a specific IP)
- IP list filtering (packets involving any IP from a list)
- IP pair filtering (packets between two specific IPs)

Author: PVParser Team
"""

import os
import sys
from typing import List, Tuple, Set, Optional
from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP
import ipaddress


def is_valid_ip(ip_str: str) -> bool:
    """
    Check if a string represents a valid IP address.
    
    Args:
        ip_str (str): IP address string to validate
        
    Returns:
        bool: True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def normalize_ip(ip_str: str) -> str:
    """
    Normalize IP address string (remove leading zeros, etc.).
    
    Args:
        ip_str (str): IP address string to normalize
        
    Returns:
        str: Normalized IP address string
    """
    try:
        return str(ipaddress.ip_address(ip_str))
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip_str}")


def filter_by_single_ip(input_pcap: str, output_pcap: str, target_ip: str) -> int:
    """
    Filter packets involving a single IP address.
    
    Args:
        input_pcap (str): Input pcap file path
        output_pcap (str): Output pcap file path
        target_ip (str): Target IP address to filter
        
    Returns:
        int: Number of packets kept in the filtered file
    """
    if not is_valid_ip(target_ip):
        raise ValueError(f"Invalid IP address: {target_ip}")
    
    target_ip = normalize_ip(target_ip)
    packets = rdpcap(input_pcap)
    filtered_packets = list()
    
    print(f"Filtering packets involving IP: {target_ip}")
    
    # Identify packets directly involving target IP
    for i, packet in enumerate(packets):
        if not packet.haslayer(IP):
            continue
            
        ip = packet[IP]
        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        
        # Check if packet involves target IP
        if src_ip == target_ip or dst_ip == target_ip:
            filtered_packets.append(packet)
    
    # Write filtered packets
    wrpcap(output_pcap, filtered_packets)
    
    print(f"Kept {len(filtered_packets)} packets out of {len(packets)} total packets")
    return len(filtered_packets)


def filter_by_ip_list(input_pcap: str, output_pcap: str, ip_list: List[str]) -> int:
    """
    Filter packets involving any IP from a list.
    
    Args:
        input_pcap (str): Input pcap file path
        output_pcap (str): Output pcap file path
        ip_list (List[str]): List of IP addresses to filter
        
    Returns:
        int: Number of packets kept in the filtered file
    """
    # Validate and normalize all IPs
    normalized_ips = set()
    for ip in ip_list:
        if not is_valid_ip(ip):
            raise ValueError(f"Invalid IP address: {ip}")
        normalized_ips.add(normalize_ip(ip))
    
    if not normalized_ips:
        raise ValueError("IP list cannot be empty")
    
    packets = rdpcap(input_pcap)
    filtered_packets = list()
    
    print(f"Filtering packets involving IPs: {list(normalized_ips)}")
    
    # Identify packets directly involving any target IP
    for i, packet in enumerate(packets):
        if not packet.haslayer(IP):
            continue
            
        ip = packet[IP]
        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        
        # Check if packet involves any target IP
        if src_ip in normalized_ips or dst_ip in normalized_ips:
            filtered_packets.append(packet)
    
    # Write filtered packets
    wrpcap(output_pcap, filtered_packets)
    
    print(f"Kept {len(filtered_packets)} packets out of {len(packets)} total packets")
    return len(filtered_packets)


def filter_by_ip_pair(input_pcap: str, output_pcap: str, ip1: str, ip2: str) -> int:
    """
    Filter packets between two specific IP addresses.
    
    Args:
        input_pcap (str): Input pcap file path
        output_pcap (str): Output pcap file path
        ip1 (str): First IP address
        ip2 (str): Second IP address
        
    Returns:
        int: Number of packets kept in the filtered file
    """
    if not is_valid_ip(ip1) or not is_valid_ip(ip2):
        raise ValueError(f"Invalid IP address: {ip1 if not is_valid_ip(ip1) else ip2}")
    
    ip1 = normalize_ip(ip1)
    ip2 = normalize_ip(ip2)
    
    if ip1 == ip2:
        raise ValueError("Both IP addresses cannot be the same")
    
    packets = rdpcap(input_pcap)
    filtered_packets = list()
    
    print(f"Filtering packets between IPs: {ip1} and {ip2}")
    
    # Identify packets directly between the two IPs
    for i, packet in enumerate(packets):
        if not packet.haslayer(IP):
            continue
            
        ip = packet[IP]
        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        
        # Check if packet is between the two target IPs
        if (src_ip == ip1 and dst_ip == ip2) or (src_ip == ip2 and dst_ip == ip1):
            filtered_packets.append(packet)
    
    # Write filtered packets
    wrpcap(output_pcap, filtered_packets)
    
    print(f"Kept {len(filtered_packets)} packets out of {len(packets)} total packets")
    return len(filtered_packets)


def get_packet_statistics(pcap_file: str) -> dict:
    """
    Get statistics about IP addresses in a pcap file.
    
    Args:
        pcap_file (str): Path to pcap file
        
    Returns:
        dict: Statistics including unique IPs, packet counts, etc.
    """
    packets = rdpcap(pcap_file)
    ip_counts = {}
    total_packets = len(packets)
    ip_packets = 0
    
    for packet in packets:
        if packet.haslayer(IP):
            ip_packets += 1
            ip = packet[IP]
            src_ip = str(ip.src)
            dst_ip = str(ip.dst)
            
            ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
            ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
    
    # Sort IPs by packet count
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    
    return {
        "total_packets": total_packets,
        "ip_packets": ip_packets,
        "unique_ips": len(ip_counts),
        "ip_counts": dict(sorted_ips[:10]),  # Top 10 IPs
        "all_ips": list(ip_counts.keys())
    }


def test_ip_filtering(pcap_file: Optional[str] = None):
    """
    Test function for IP filtering capabilities.
    
    Args:
        pcap_file (Optional[str]): Path to test pcap file (optional)
    """
    if pcap_file is None:
        # Look for test files in common locations
        test_locations = [
            "dataset/test/test.pcap",
            "dataset/scada/test.pcap", 
            "dataset/swat/test.pcap",
            "test.pcap"
        ]
        
        for loc in test_locations:
            if os.path.exists(loc):
                pcap_file = loc
                break
    
    if pcap_file is None or not os.path.exists(pcap_file):
        print("No test pcap file found. Please provide a valid pcap file path.")
        return
    
    print(f"Testing IP filtering with file: {pcap_file}")
    
    # Get statistics first
    """
    print("\n1. Getting packet statistics...")
    try:
        stats = get_packet_statistics(pcap_file)
        print(f"Total packets: {stats['total_packets']}")
        print(f"IP packets: {stats['ip_packets']}")
        print(f"Unique IPs: {stats['unique_ips']}")
        print(f"Top 5 IPs by packet count:")
        for ip, count in list(stats['ip_counts'].items())[:5]:
            print(f"  {ip}: {count} packets")
        
        if len(stats['all_ips']) < 2:
            print("Not enough unique IPs for testing. Need at least 2 IPs.")
            return
            
        test_ip1 = stats['all_ips'][0]
        test_ip2 = stats['all_ips'][1]
        
    except Exception as e:
        print(f"Error getting statistics: {e}")
        return
    """
    test_ip1 = "192.168.1.10"
    test_ip2 = "192.168.1.200"
    # Test single IP filtering
    print(f"\n2. Testing single IP filtering with {test_ip1}...")
    try:
        output_file = pcap_file.replace(".pcap", "_single_ip.pcap")
        kept_count = filter_by_single_ip(pcap_file, output_file, test_ip1)
        print(f"Single IP filtering completed. Kept {kept_count} packets.")
        
        # Clean up test file
        if os.path.exists(output_file):
            os.remove(output_file)
            print(f"Cleaned up test file: {output_file}")
            
    except Exception as e:
        print(f"Error in single IP filtering: {e}")
    
    # Test IP list filtering
    print(f"\n3. Testing IP list filtering with [{test_ip1}, {test_ip2}]...")
    try:
        output_file = pcap_file.replace(".pcap", "_ip_list.pcap")
        kept_count = filter_by_ip_list(pcap_file, output_file, [test_ip1, test_ip2])
        print(f"IP list filtering completed. Kept {kept_count} packets.")
        
        # Clean up test file
        if os.path.exists(output_file):
            os.remove(output_file)
            print(f"Cleaned up test file: {output_file}")
            
    except Exception as e:
        print(f"Error in IP list filtering: {e}")
    
    # Test IP pair filtering
    print(f"\n4. Testing IP pair filtering between {test_ip1} and {test_ip2}...")
    try:
        output_file = pcap_file.replace(".pcap", "_ip_pair.pcap")
        kept_count = filter_by_ip_pair(pcap_file, output_file, test_ip1, test_ip2)
        print(f"IP pair filtering completed. Kept {kept_count} packets.")
        
        # Clean up test file
        if os.path.exists(output_file):
            os.remove(output_file)
            print(f"Cleaned up test file: {output_file}")
            
    except Exception as e:
        print(f"Error in IP pair filtering: {e}")
    
    print("\nAll IP filtering tests completed!")


if __name__ == "__main__":
    pcap_file = "dataset/swat/Dec2019_00000_20191206100500_00000w_filtered.pcap"
    test_ip1 = "192.168.1.10"
    test_ip2 = "192.168.1.200"
    output_file = pcap_file.replace(".pcap", f"({test_ip1}-{test_ip2}).pcap")
    filter_by_ip_pair(pcap_file, output_file, test_ip1, test_ip2)