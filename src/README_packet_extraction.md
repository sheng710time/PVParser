# Packet Directed Length Sequence Extraction Tool

This tool is used to extract directed length sequences from PCAP files, specifically designed for Industrial Control System (ICS) network traffic analysis.

## Features

- ✅ Extract packet length sequences
- ✅ Identify packet direction (inbound/outbound)
- ✅ Support multiple ICS protocol filtering (Modbus, S7, EtherNet/IP)
- ✅ Include timestamp information
- ✅ Length normalization
- ✅ Statistical analysis
- ✅ Export to CSV format

## File Description

- `packet_length_extractor.py` - Main extraction functionality module
- `test_length_extractor.py` - Complete test script
- `example_usage.py` - Simple usage example
- `ics_basis.py` - ICS protocol port definitions

## Quick Start

### 1. Basic Usage

```python
from packet_length_extractor import extract_directed_length_sequence

# Extract directed length sequence for all TCP packets
packets_info = extract_directed_length_sequence("your_file.pcap")

# Display results
for pkt in packets_info[:5]:
    print(f"Length: {pkt['length']}, Direction: {pkt['direction']}")
```

### 2. Protocol Filtering

```python
# Extract only Modbus protocol packets
modbus_packets = extract_directed_length_sequence("your_file.pcap", protocol='modbus')

# Extract only S7 protocol packets
s7_packets = extract_directed_length_sequence("your_file.pcap", protocol='s7')

# Extract only EtherNet/IP protocol packets
enip_packets = extract_directed_length_sequence("your_file.pcap", protocol='enip')
```

### 3. Direction Filtering

```python
from packet_length_extractor import extract_length_sequence_only

# Extract only inbound packet length sequence
inbound_lengths = extract_length_sequence_only("your_file.pcap", direction='inbound')

# Extract only outbound packet length sequence
outbound_lengths = extract_length_sequence_only("your_file.pcap", direction='outbound')
```

### 4. Directed Sequence

```python
from packet_length_extractor import extract_directed_sequence

# Extract directed sequence (length + direction)
directed_seq = extract_directed_sequence("your_file.pcap")
# Returns format: [(length, direction), (length, direction), ...]
```

### 5. Statistics

```python
from packet_length_extractor import analyze_sequence_statistics

packets_info = extract_directed_length_sequence("your_file.pcap")
stats = analyze_sequence_statistics(packets_info)

print(f"Total packets: {stats['total_packets']}")
print(f"Average length: {stats['avg_length']}")
print(f"Inbound packets: {stats['inbound_count']}")
print(f"Outbound packets: {stats['outbound_count']}")
```

### 6. Save to CSV

```python
from packet_length_extractor import save_sequence_to_csv

packets_info = extract_directed_length_sequence("your_file.pcap")
save_sequence_to_csv(packets_info, "output.csv")
```

## Advanced Usage

### With Timestamp and Normalization

```python
packets_info = extract_directed_length_sequence(
    "your_file.pcap",
    protocol='modbus',
    include_timestamp=True,  # Include timestamp
    normalize=True          # Normalize length
)

# Access detailed information
for pkt in packets_info:
    print(f"Length: {pkt['length']}")
    print(f"Normalized length: {pkt['normalized_length']}")
    print(f"Timestamp: {pkt['timestamp']}")
    print(f"Relative time: {pkt['relative_time']}")
```

## Supported Protocols

| Protocol | Ports | Description |
|----------|-------|-------------|
| Modbus/TCP | 502, 503 | Industrial communication protocol |
| S7comm | 102 | Siemens S7 protocol |
| EtherNet/IP | 44818 | Industrial Ethernet protocol |

## Output Format

Each packet information contains the following fields:

- `index`: Packet index in the sequence
- `length`: Total packet length (bytes)
- `direction`: Direction ('inbound' or 'outbound')
- `src_ip`: Source IP address
- `dst_ip`: Destination IP address
- `protocol`: IP protocol number
- `src_port`: Source port (TCP/UDP)
- `dst_port`: Destination port (TCP/UDP)
- `timestamp`: Timestamp (if enabled)
- `relative_time`: Relative time (if enabled)
- `normalized_length`: Normalized length (if enabled)

## Run Examples

```bash
# Run simple example
python example_usage.py

# Run complete test
python test_length_extractor.py
```

## Notes

1. **File Size**: Large files may take a long time to process
2. **Memory Usage**: Be aware of memory usage when processing large numbers of packets
3. **Protocol Identification**: Protocol identification is based on port numbers and may not be completely accurate
4. **Direction Determination**: Direction is determined based on the source IP of the first packet as the internal IP

## Dependencies

- scapy
- numpy
- pandas
- pathlib

Install dependencies:
```bash
pip install scapy numpy pandas
``` 