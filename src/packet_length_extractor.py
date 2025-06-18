from pathlib import Path
from scapy.all import PcapReader, IP, TCP, UDP
import numpy as np
import pandas as pd
from typing import List, Tuple, Dict
import time
from basis.ics_basis import ics_protocol_ports
from util.preprocessing_pcap import is_ics_port_by_protocol


def extract_directed_length_sequence(pcap_file: str, 
                                   protocol: str = None,
                                   include_timestamp: bool = True,
                                   normalize: bool = False) -> List[Dict]:
    """
    Extract directed length sequence from packet capture file
    
    Parameters:
    -----------
    pcap_file : str
        Path to the PCAP file
    protocol : str, optional
        Protocol type ('s7', 'modbus', 'enip'), if None then process all TCP packets
    include_timestamp : bool
        Whether to include timestamp information
    normalize : bool
        Whether to normalize the packet lengths
        
    Returns:
    --------
    List[Dict]: List of dictionaries containing information for each packet
    """
    packets_info = []
    dir_len_sequence = []
    
    # Get ports for the specified protocol
    target_ports = ics_protocol_ports.get(protocol, []) if protocol else []
    
    with PcapReader(pcap_file) as reader:
        for i, packet in enumerate(reader):
            # Only process IP packets
            if not packet.haslayer(IP):
                continue
                
            # If protocol is specified, only process packets of that protocol
            if protocol and target_ports:
                if not (packet.haslayer(TCP) and 
                       (packet[TCP].sport in target_ports or packet[TCP].dport in target_ports)):
                    continue
            
            # Extract basic information
            ip_layer = packet[IP]
            packet_info = {
                'index': i,
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'length': len(packet)
            }
            # Add transport layer information
            tcp_layer = packet[TCP]
            packet_info.update({
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport
            })
            
            # Determine direction (based on source and destination IP)
            # Assume the first IP seen is the "internal" IP
            if is_ics_port_by_protocol(packet[TCP].dport, protocol):
                packet_info['direction'] = "C"
            elif is_ics_port_by_protocol(packet[TCP].sport, protocol):
                packet_info['direction'] = "S"
            
            # Add timestamp information
            if include_timestamp:
                packet_info['timestamp'] = packet.time
                
            packet_info["dir_len"] = f"{f"{packet_info['direction']}-{packet_info['length']}"}"
            
            dir_len_sequence.append(f"{packet_info['direction']}-{packet_info['length']}")
            
    return packets_info, dir_len_sequence


def save_sequence_to_csv(packets_info: List[Dict], output_file: str):
    """
    Save sequence information to CSV file
    
    Parameters:
    -----------
    packets_info : List[Dict]
        List of packet information
    output_file : str
        Output file path
    """
    df = pd.DataFrame(packets_info)
    df.to_csv(output_file, index=False)
    print(f"Sequence information saved to: {output_file}")


def analyze_sequence_statistics(packets_info: List[Dict]) -> Dict:
    """
    Analyze sequence statistics
    
    Parameters:
    -----------
    packets_info : List[Dict]
        List of packet information
        
    Returns:
    --------
    Dict: Statistical information
    """
    if not packets_info:
        return {}
    
    lengths = [p['length'] for p in packets_info]
    directions = [p['direction'] for p in packets_info]
    
    stats = {
        'total_packets': len(packets_info),
        'avg_length': np.mean(lengths),
        'std_length': np.std(lengths),
        'min_length': np.min(lengths),
        'max_length': np.max(lengths),
        'C_count': directions.count('C'),
        'S_count': directions.count('S')
    }
    
    return stats


def main():
    """
    Example usage
    """
    # Example: process a pcap file
    pcap_file = "dataset/test/test_100.pcap"
    
    if Path(pcap_file).exists():
        print("Extracting directed length sequence...")
        
        # Extract all information
        packets_info, = extract_directed_length_sequence(pcap_file, protocol='modbus')
        
        # Save to CSV
        output_file = pcap_file.replace('.pcap', '_length_sequence.csv')
        save_sequence_to_csv(packets_info, output_file)
        
        # Analyze statistics
        stats = analyze_sequence_statistics(packets_info)
        print("\nStatistics:")
        for key, value in stats.items():
            print(f"{key}: {value}")
        
    else:
        print(f"File not found: {pcap_file}")


if __name__ == "__main__":
    main() 