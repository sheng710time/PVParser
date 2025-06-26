from pathlib import Path
from scapy.all import PcapReader, IP, TCP
import numpy as np
import pandas as pd
from typing import List, Tuple, Dict
import time
from basis.ics_basis import ics_protocol_ports
from util.preprocessing_pcap import is_ics_port_by_protocol
from decimal import Decimal
from difflib import SequenceMatcher
from collections import defaultdict
import statistics


def extract_directed_length_sequence_with_control(pcap_file: str, protocol: str, include_timestamp: bool = True):
    """
    Extract directed length sequence from packet capture file with function code for modbus
    
    Parameters:
    -----------
    pcap_file : str
        Path to the PCAP file
    protocol : str, optional
        Protocol type ('s7', 'modbus', 'enip'), if None then process all TCP packets
    include_timestamp : bool
        Whether to include timestamp information
        
    Returns:
    --------
    List[Dict]: List of dictionaries containing information for each packet
    """
    packet_info_list = []
    dir_len_sequence = []
    dir_len_con_sequence = []
    
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
            
            # Extract function code for modbus protocol
            control = 0  # Default value
            if protocol == 'modbus' and packet.haslayer(TCP):
                try:
                    # Get TCP payload
                    tcp_payload = bytes(packet[TCP].payload)
                    # Check if this is a Modbus packet (should have enough data and proper structure)
                    if len(tcp_payload) >= 8:
                        # For Modbus TCP, check if it has proper MBAP header structure
                        # MBAP header: Transaction ID (2 bytes) + Protocol ID (2 bytes) + Length (2 bytes) + Unit ID (1 byte)
                        # Then function code (1 byte)
                        transaction_id = tcp_payload[0:2]
                        protocol_id = tcp_payload[2:4]
                        length = tcp_payload[4:6]
                        unit_id = tcp_payload[6]
                        
                        # Check if this looks like a valid Modbus TCP packet
                        # Protocol ID should be 0x0000 for Modbus
                        if protocol_id == b'\x00\x00' and unit_id <= 255:
                            control = tcp_payload[7]
                        else:
                            control = 0
                    else:
                        # Not a valid Modbus packet
                        control = 0
                except:
                    control = 0
            packet_info['control'] = control
            
            # Add timestamp information
            if include_timestamp:
                packet_info['timestamp'] = packet.time
                
            # Create dir-len-func format
            packet_info["dir_len"] = f"{packet_info['direction']}-{packet_info['length']}"
            packet_info["dir_len_con"] = f"{packet_info['direction']}-{packet_info['length']}-{packet_info['control']}"
            packet_info_list.append(packet_info)
            dir_len_sequence.append((packet_info['timestamp'], f"{packet_info['direction']}-{packet_info['length']}"))
            dir_len_con_sequence.append((packet_info['timestamp'], f"{packet_info['direction']}-{packet_info['length']}-{packet_info['control']}"))
            
    return packet_info_list, dir_len_con_sequence, dir_len_sequence


def extract_directed_length_sequence(pcap_file: str, protocol: str, include_timestamp: bool = True):
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
    packet_info_list = []
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
                
            packet_info["dir_len"] = f"{packet_info['direction']}-{packet_info['length']}"
            packet_info_list.append(packet_info)
            dir_len_sequence.append((packet_info['timestamp'], f"{packet_info['direction']}-{packet_info['length']}"))
            
    return packet_info_list, dir_len_sequence


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


def read_sequence_from_csv(csv_file: str, sequence_name: str) -> Tuple[List[Dict], List[Tuple]]:
    """
    Read sequence information from CSV file
    
    Parameters:
    -----------
    csv_file : str
        Path to the CSV file
        
    Returns:
    --------
    Tuple[List[Dict], List[Tuple]]: (packets_info, dir_len_sequence)
    """
    if not Path(csv_file).exists():
        print(f"CSV file not found: {csv_file}")
        return [], []
    
    try:
        # Read CSV file
        df = pd.read_csv(csv_file)
        
        # Convert DataFrame to list of dictionaries
        packets_info = df.to_dict('records')
        
        # Create dir_len_sequence from packets_info
        dir_len_sequence = []
        for packet in packets_info:
            if sequence_name in packet:
                dir_len_sequence.append((packet['timestamp'], packet[sequence_name]))
            else:
                if 'timestamp' in packet:
                    fields = []
                    if 'direction' in packet:
                        fields.append(str(packet['direction']))
                    if 'length' in packet:
                        fields.append(str(packet['length']))
                    if 'control' in packet:
                        fields.append(str(packet['control']))
                    if fields:
                        dir_len = '-'.join(fields)
                        dir_len_sequence.append((packet['timestamp'], dir_len))
        
        print(f"Successfully read {len(packets_info)} packets from {csv_file}")
        return packets_info, dir_len_sequence
        
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return [], []


def split_sequence_by_pattern(dir_len_sequence: List[Tuple], pattern: List[str]):
    """
    Split dir_len_sequence by specified pattern and mark matched/unmatched elements
    
    Parameters:
    -----------
    dir_len_sequence : List[Tuple]
        List of tuples in format (timestamp, "C-100")
    pattern : List[str]
        Pattern to split by, e.g. ["C-100", "S-200"]
        
    Returns:
    --------
    Tuple[List[Tuple], List[Tuple]]: (split_sequence, matched_indices)
        split_sequence: List of tuples with matched flag, format (timestamp, "C-100", matched)
        matched_indices: List of tuples indicating start and end indices of matched patterns
    """
    if not pattern or not dir_len_sequence:
        # Return original sequence with unmatched flag
        return [(item[0], item[1], False) for item in dir_len_sequence], [], 0.0, 0.0, 0.0
    
    pattern_len = len(pattern)
    sequence_len = len(dir_len_sequence)
    
    if pattern_len > sequence_len:
        # Return original sequence with unmatched flag
        return [(item[0], item[1], False) for item in dir_len_sequence], [], 0.0, 0.0, 0.0
    
    # Initialize split_sequence with unmatched flags
    split_sequence = [(item[0], item[1], False) for item in dir_len_sequence]
    
    i = 0
    matched_indices = []
    matched_start_packets = []
    while i <= sequence_len - pattern_len:
        # Check if pattern matches at current position
        match = True
        for j in range(pattern_len):
            if dir_len_sequence[i + j][1] != pattern[j]:
                match = False
                break
        
        if match:
            # Mark the matched elements
            for j in range(pattern_len):
                split_sequence[i + j] = (dir_len_sequence[i + j][0], dir_len_sequence[i + j][1], True)
            i += pattern_len
            matched_indices.append((i, i + pattern_len - 1))
            matched_start_packets.append(dir_len_sequence[i])
        else:
            i += 1
    # Calculate match ratio
    matched_packets = sum(1 for _, _, matched in split_sequence if matched)
    total_packets = len(dir_len_sequence)
    match_ratio = matched_packets / total_packets if total_packets > 0 else 0.0
    
    # Calculate average interval between matched start packets and standard deviation
    if matched_start_packets:
        intervals = [matched_start_packets[i][0] - matched_start_packets[i - 1][0] for i in range(1, len(matched_start_packets))]
        avg_interval = np.mean(intervals)
        std_interval = np.std(intervals)
    else:
        avg_interval = 0.0
        std_interval = 0.0
    
    # Calculate and return match rate
    return split_sequence, matched_indices, match_ratio, avg_interval, std_interval


def main():
    """
    Example usage
    """
    # Example: process a pcap file
    pcap_file = "dataset/swat/Dec2019_00000_20191206100500_00000w_filtered(20-100).pcap"
    
    if Path(pcap_file).exists():
        print("Extracting directed length sequence...")
        
        # Extract all information
        packets_info, dir_len_sequence = extract_directed_length_sequence(pcap_file, protocol='enip')
        for dir_len in dir_len_sequence:
            print(dir_len)
        
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