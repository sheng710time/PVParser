#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script for packet directed length sequence extraction functionality
"""

from packet_length_extractor import *
from pathlib import Path
import sys


def test_extraction():
    """Test extraction functionality"""
    
    # Test file paths
    test_files = [
        "dataset/test/test_100.pcap",
        "dataset/test/test_100_filtered.pcap"
    ]
    
    for pcap_file in test_files:
        if not Path(pcap_file).exists():
            print(f"File not found: {pcap_file}")
            continue
            
        print(f"\n{'='*50}")
        print(f"Processing file: {pcap_file}")
        print(f"{'='*50}")
        
        try:
            # 1. Extract complete directed length sequence
            print("\n1. Extracting complete directed length sequence...")
            packets_info = extract_directed_length_sequence(
                pcap_file, 
                protocol='modbus',  # Can be changed to 's7', 'enip' or None
                include_timestamp=True,
                normalize=True
            )
            
            print(f"Extracted information for {len(packets_info)} packets")
            
            # 2. Display information for first few packets
            if packets_info:
                print("\nInformation for first 5 packets:")
                for i, pkt in enumerate(packets_info[:5]):
                    print(f"  Packet {i+1}: Length={pkt['length']}, Direction={pkt['direction']}, "
                          f"SourceIP={pkt['src_ip']}, DestIP={pkt['dst_ip']}")
            
            # 3. Extract only length sequence
            print("\n2. Extracting only length sequence...")
            length_seq = extract_length_sequence_only(pcap_file, protocol='modbus')
            print(f"Length sequence (first 10): {length_seq[:10]}")
            
            # 4. Extract directed sequence
            print("\n3. Extracting directed sequence...")
            directed_seq = extract_directed_sequence(pcap_file, protocol='modbus')
            print(f"Directed sequence (first 10): {directed_seq[:10]}")
            
            # 5. Analyze statistics
            print("\n4. Statistics:")
            stats = analyze_sequence_statistics(packets_info)
            for key, value in stats.items():
                print(f"  {key}: {value}")
            
            # 6. Save to CSV
            print("\n5. Saving to CSV file...")
            output_file = pcap_file.replace('.pcap', '_length_sequence.csv')
            save_sequence_to_csv(packets_info, output_file)
            
        except Exception as e:
            print(f"Error processing file: {e}")
            import traceback
            traceback.print_exc()


def test_different_protocols():
    """Test extraction for different protocols"""
    
    pcap_file = "dataset/test/test_100.pcap"
    if not Path(pcap_file).exists():
        print(f"File not found: {pcap_file}")
        return
    
    protocols = ['modbus', 's7', 'enip', None]  # None means all TCP packets
    
    print(f"\n{'='*60}")
    print("Testing extraction for different protocols")
    print(f"{'='*60}")
    
    for protocol in protocols:
        protocol_name = protocol if protocol else "all_tcp"
        print(f"\nProtocol: {protocol_name}")
        
        try:
            packets_info = extract_directed_length_sequence(pcap_file, protocol=protocol)
            print(f"  Packet count: {len(packets_info)}")
            
            if packets_info:
                stats = analyze_sequence_statistics(packets_info)
                print(f"  Average length: {stats.get('avg_length', 0):.2f}")
                print(f"  Inbound packets: {stats.get('inbound_count', 0)}")
                print(f"  Outbound packets: {stats.get('outbound_count', 0)}")
                
        except Exception as e:
            print(f"  Error: {e}")


def test_direction_filtering():
    """Test direction filtering"""
    
    pcap_file = "dataset/test/test_100.pcap"
    if not Path(pcap_file).exists():
        print(f"File not found: {pcap_file}")
        return
    
    print(f"\n{'='*60}")
    print("Testing direction filtering")
    print(f"{'='*60}")
    
    directions = ['inbound', 'outbound', None]
    
    for direction in directions:
        direction_name = direction if direction else "all"
        print(f"\nDirection: {direction_name}")
        
        try:
            length_seq = extract_length_sequence_only(pcap_file, protocol='modbus', direction=direction)
            print(f"  Packet count: {len(length_seq)}")
            if length_seq:
                print(f"  First 5 lengths: {length_seq[:5]}")
                
        except Exception as e:
            print(f"  Error: {e}")


if __name__ == "__main__":
    print("Starting test for packet directed length sequence extraction functionality...")
    
    # Run all tests
    test_extraction()
    test_different_protocols()
    test_direction_filtering()
    
    print("\nTesting completed!") 