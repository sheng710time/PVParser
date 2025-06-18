#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simple usage example: Extract packet directed length sequence
"""

from packet_length_extractor import *
from pathlib import Path


def simple_example():
    """Simple example"""
    
    # 1. Basic usage - Extract directed length sequence for all TCP packets
    pcap_file = "dataset/test/test_100.pcap"
    
    if not Path(pcap_file).exists():
        print(f"Please ensure file exists: {pcap_file}")
        return
    
    print("=== Basic Usage ===")
    
    # Extract information for all TCP packets
    packets_info = extract_directed_length_sequence(pcap_file)
    print(f"Total packets extracted: {len(packets_info)}")
    
    # Display information for first few packets
    for i, pkt in enumerate(packets_info[:3]):
        print(f"Packet {i+1}: Length={pkt['length']}, Direction={pkt['direction']}")
    
    print("\n=== Protocol Filtering ===")
    
    # Extract only Modbus protocol packets
    modbus_packets = extract_directed_length_sequence(pcap_file, protocol='modbus')
    print(f"Modbus packet count: {len(modbus_packets)}")
    
    # Extract only S7 protocol packets
    s7_packets = extract_directed_length_sequence(pcap_file, protocol='s7')
    print(f"S7 packet count: {len(s7_packets)}")
    
    print("\n=== Direction Filtering ===")
    
    # Extract only inbound packet length sequence
    inbound_lengths = extract_length_sequence_only(pcap_file, direction='inbound')
    print(f"Inbound packet count: {len(inbound_lengths)}")
    print(f"Inbound packet lengths (first 5): {inbound_lengths[:5]}")
    
    # Extract only outbound packet length sequence
    outbound_lengths = extract_length_sequence_only(pcap_file, direction='outbound')
    print(f"Outbound packet count: {len(outbound_lengths)}")
    print(f"Outbound packet lengths (first 5): {outbound_lengths[:5]}")
    
    print("\n=== Directed Sequence ===")
    
    # Extract directed sequence (length + direction)
    directed_seq = extract_directed_sequence(pcap_file)
    print(f"Directed sequence (first 5): {directed_seq[:5]}")
    
    print("\n=== Statistics ===")
    
    # Analyze statistics
    stats = analyze_sequence_statistics(packets_info)
    print("Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n=== Save to CSV ===")
    
    # Save to CSV file
    output_file = pcap_file.replace('.pcap', '_example_output.csv')
    save_sequence_to_csv(packets_info, output_file)


def advanced_example():
    """Advanced example"""
    
    pcap_file = "dataset/test/test_100.pcap"
    
    if not Path(pcap_file).exists():
        print(f"Please ensure file exists: {pcap_file}")
        return
    
    print("\n=== Advanced Usage ===")
    
    # Extract information with timestamp and normalized length
    packets_info = extract_directed_length_sequence(
        pcap_file,
        protocol='modbus',
        include_timestamp=True,
        normalize=True
    )
    
    if packets_info:
        print(f"Extracted {len(packets_info)} Modbus packets")
        
        # Display detailed information
        print("\nDetailed information for first 3 packets:")
        for i, pkt in enumerate(packets_info[:3]):
            print(f"Packet {i+1}:")
            print(f"  Index: {pkt['index']}")
            print(f"  Length: {pkt['length']}")
            print(f"  Normalized length: {pkt.get('normalized_length', 'N/A')}")
            print(f"  Direction: {pkt['direction']}")
            print(f"  Source IP: {pkt['src_ip']}")
            print(f"  Destination IP: {pkt['dst_ip']}")
            print(f"  Source port: {pkt.get('src_port', 'N/A')}")
            print(f"  Destination port: {pkt.get('dst_port', 'N/A')}")
            print(f"  Timestamp: {pkt.get('timestamp', 'N/A')}")
            print(f"  Relative time: {pkt.get('relative_time', 'N/A')}")
            print()


if __name__ == "__main__":
    print("Packet Directed Length Sequence Extraction Example")
    print("=" * 50)
    
    simple_example()
    advanced_example()
    
    print("\nExample completed!")
    print("\nUsage instructions:")
    print("1. Modify the pcap_file variable to point to your pcap file")
    print("2. Adjust the protocol parameter as needed ('modbus', 's7', 'enip', None)")
    print("3. Use the direction parameter to filter direction ('inbound', 'outbound', None)")
    print("4. Use include_timestamp and normalize parameters to control output format") 