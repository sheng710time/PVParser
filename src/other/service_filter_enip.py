import pyshark
from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import TCP, IP


def is_padding_payload(payload):
    """
    Check if the payload is just padding (zeros or minimal data).
    
    Args:
        payload (bytes): The TCP payload to check
        
    Returns:
        bool: True if payload is padding, False otherwise
    """
    if not payload:
        return True
    
    # Check if all bytes are zero (common padding)
    if all(b == 0 for b in payload):
        return True
    
    # Check for common padding patterns
    # Some systems use repeated bytes as padding
    if len(payload) >= 2:
        first_byte = payload[0]
        if all(b == first_byte for b in payload):
            return True
    
    return False


# =============================================================================
# Core CIP Service Mapping Functions
# =============================================================================


def get_cip_service_map(pcap_path):
    """
    Use pyshark to build a mapping from 0-based packet index to CIP service code.

    Args:
        pcap_path (str): Path to the pcap file

    Returns:
        dict[int, int]: {packet_index: cip_service_code}
    """
    # Use use_json=True to avoid event loop issues in Jupyter environments
    cap = pyshark.FileCapture(pcap_path, display_filter="enip", use_json=True)
    service_map = {}
    for pkt in cap:
        try:
            if hasattr(pkt, "cip"):
                if hasattr(pkt.cip, "service"):
                    service_code = int(pkt.cip.service, 16)
                elif hasattr(pkt.cip, "service_id"):
                    service_code = int(pkt.cip.service_id, 16)
                elif hasattr(pkt.cip, "service_code"):
                    service_code = int(pkt.cip.service_code, 16)
                else:
                    continue
                # pyshark pkt.number is 1-based, convert to 0-based for indexing with scapy packets
                service_map[int(pkt.number) - 1] = service_code
        except Exception:
            continue
    cap.close()
    return service_map


def get_cip_service_map_alternative(pcap_path):
    """
    Alternative implementation that avoids pyshark event loop issues.
    Uses subprocess to call tshark directly.

    Args:
        pcap_path (str): Path to the pcap file

    Returns:
        dict[int, int]: {packet_index: cip_service_code}
    """
    import subprocess
    import json

    try:
        # Use tshark directly with JSON output
        cmd = [
            "tshark",
            "-r",
            pcap_path,
            "-Y",
            "enip",
            "-T",
            "json",
            "-e",
            "cip.service",
            "-e",
            "cip.service_id",
            "-e",
            "cip.service_code",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)

        service_map = {}
        for i, packet in enumerate(data):
            if "_source" in packet and "layers" in packet["_source"]:
                layers = packet["_source"]["layers"]
                cip_layer = layers.get("cip", {})

                service_code = None
                if "cip.service" in cip_layer:
                    service_code = int(cip_layer["cip.service"][0], 16)
                elif "cip.service_id" in cip_layer:
                    service_code = int(cip_layer["cip.service_id"][0], 16)
                elif "cip.service_code" in cip_layer:
                    service_code = int(cip_layer["cip.service_code"][0], 16)

                if service_code is not None:
                    service_map[i] = service_code

        return service_map
    except Exception as e:
        print(f"Alternative method failed: {e}")
        return {}


def get_cip_service_map_safe(pcap_path):
    """
    Safe wrapper that tries the original method first, then falls back to alternative.
    This handles Jupyter environment event loop issues.

    Args:
        pcap_path (str): Path to the pcap file

    Returns:
        dict[int, int]: {packet_index: cip_service_code}
    """
    try:
        return get_cip_service_map(pcap_path)
    except RuntimeError as e:
        if "event loop is already running" in str(e):
            print("Warning: Event loop issue detected. Using alternative method...")
            return get_cip_service_map_alternative(pcap_path)
        else:
            raise e


# =============================================================================
# EtherNet/IP Filtering Functions
# =============================================================================


def filter_enip_remove_service(input_pcap, output_pcap, service_codes, max_search=500):
    """
    Filter EtherNet/IP packets to REMOVE those with specified service codes.
    This function removes packets with the specified service codes and their related ACK/response packets.

    Args:
        input_pcap (str): Input pcap file path
        output_pcap (str): Output pcap file path
        service_codes (list): List of service codes to REMOVE
        max_search (int): Maximum packets to search forward for responses
    """
    # Step 1: Get precise CIP service codes from pyshark (using safe version)
    cip_service_map = get_cip_service_map_safe(input_pcap)

    packets = rdpcap(input_pcap)
    indexes_to_remove = set()
    response_records = []

    # Step 2: Identify request packets by consulting the pyshark CIP service map
    request_records = []
    for i, pkt in enumerate(packets):
        if i not in cip_service_map:
            continue
        cip_service = cip_service_map[i]
        if cip_service in service_codes and pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].dport == 44818:  # Requestor's port is 44818
            tcp = pkt[TCP]
            ip = pkt[IP]
            payload_len = len(bytes(tcp.payload))
            indexes_to_remove.add(i)
            request_records.append(
                {
                    "index": i,
                    "src": ip.src,
                    "dst": ip.dst,
                    "sport": tcp.sport,
                    "dport": tcp.dport,
                    "seq": tcp.seq,
                    "payload_len": payload_len,
                    "cip_service": cip_service,
                }
            )

    # Step 3: For each request, search forward to remove ACK and response packets
    req_idx = 0
    for req in request_records:
        req_seq_end = req["seq"] + req["payload_len"]
        start_idx = req["index"] + 1
        end_idx = min(len(packets), start_idx + max_search)
        for i in range(start_idx, end_idx):
            if i in indexes_to_remove:
                continue
            pkt = packets[i]
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)

            # Responder's ACK to request (opposite direction, no payload)
            if ip.src == req["dst"] and ip.dst == req["src"] and tcp.sport == req["dport"] and tcp.dport == req["sport"] and tcp.ack == req_seq_end and is_padding_payload(payload):
                indexes_to_remove.add(i)
                continue

            # Responder's CIP response packet - find the first valid response
            if ip.src == req["dst"] and ip.dst == req["src"] and tcp.sport == req["dport"] and tcp.dport == req["sport"] and tcp.ack >= req_seq_end and not is_padding_payload(payload):
                # Get inserted request packets with the same service code
                inserted_requests = []
                for inserted_req_idx in range(req_idx+1, len(request_records)):
                    if request_records[inserted_req_idx]["index"] < i and request_records[inserted_req_idx]["cip_service"] == req["cip_service"]:
                        inserted_requests.append(request_records[inserted_req_idx])
                    else:
                        break
                # If there are inserted requests, the response is not valid
                if len(inserted_requests) > 0:
                    continue
                
                # Use pyshark map if available for this response packet
                resp_service = cip_service_map.get(i)
                # Response service code should be request service code ORed with 0x80
                if resp_service is not None and resp_service == (req["cip_service"] | 0x80):  # Using 0x80, because the 1st bit is used for a flag for request/response
                    indexes_to_remove.add(i)
                    response_records.append(
                        {
                            "index": i,
                            "src": ip.src,
                            "dst": ip.dst,
                            "sport": tcp.sport,
                            "dport": tcp.dport,
                            "seq": tcp.seq,
                            "payload_len": len(payload),
                        }
                    )
                    break
        req_idx += 1

    # Step 4: For each response, search forward for the requestor's ACK confirming the response
    for resp in response_records:
        resp_seq_end = resp["seq"] + resp["payload_len"]
        start_idx = resp["index"] + 1
        end_idx = min(len(packets), start_idx + max_search)
        for i in range(start_idx, end_idx):
            if i in indexes_to_remove:
                continue
            pkt = packets[i]
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)

            # Requestor's ACK to the response (original request direction, no payload)
            if ip.src == resp["dst"] and ip.dst == resp["src"] and tcp.sport == resp["dport"] and tcp.dport == resp["sport"] and tcp.ack == resp_seq_end and is_padding_payload(payload):
                indexes_to_remove.add(i)
                break

    # Step 5: Write out filtered packets
    filtered_packets = [
        pkt for i, pkt in enumerate(packets) if i not in indexes_to_remove
    ]
    wrpcap(output_pcap, filtered_packets)
    print(
        f"Filtered pcap saved to: {output_pcap}, removed {len(indexes_to_remove)} packets"
    )


def filter_enip_keep_service(input_pcap, output_pcap, service_codes, max_search=500):
    """
    Filter EtherNet/IP packets to KEEP only those with specified service codes and their related ACK/response packets.
    This is the opposite of filter_enip_by_service which removes specified service codes.

    Args:
        input_pcap (str): Input pcap file path
        output_pcap (str): Output pcap file path
        service_codes (list): List of service codes to KEEP
        max_search (int): Maximum packets to search forward for responses
    """
    # Step 1: Get precise CIP service codes from pyshark (using safe version)
    cip_service_map = get_cip_service_map_safe(input_pcap)

    packets = rdpcap(input_pcap)
    indexes_to_keep = set()
    response_records = []

    # Step 2: Identify request packets by consulting the pyshark CIP service map
    request_records = []
    for i, pkt in enumerate(packets):
        if i not in cip_service_map:
            continue
        cip_service = cip_service_map[i]
        if cip_service in service_codes and pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].dport == 44818:  # Requestor's port is 44818
            tcp = pkt[TCP]
            ip = pkt[IP]
            payload_len = len(bytes(tcp.payload))
            indexes_to_keep.add(i)
            request_records.append(
                {
                    "index": i,
                    "src": ip.src,
                    "dst": ip.dst,
                    "sport": tcp.sport,
                    "dport": tcp.dport,
                    "seq": tcp.seq,
                    "payload_len": payload_len,
                    "cip_service": cip_service,
                }
            )

    # Step 3: For each request, search forward to keep ACK and response packets
    req_idx = 0
    for req in request_records:
        req_seq_end = req["seq"] + req["payload_len"]
        start_idx = req["index"] + 1
        end_idx = min(len(packets), start_idx + max_search)
        for i in range(start_idx, end_idx):
            if i in indexes_to_keep:
                continue
            pkt = packets[i]
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)

            # Responder's ACK to request (opposite direction, no payload)
            if ip.src == req["dst"] and ip.dst == req["src"] and tcp.sport == req["dport"] and tcp.dport == req["sport"] and tcp.ack == req_seq_end and is_padding_payload(payload):
                indexes_to_keep.add(i)
                continue

            # Responder's CIP response packet - find the first valid response
            if ip.src == req["dst"] and ip.dst == req["src"] and tcp.sport == req["dport"] and tcp.dport == req["sport"] and tcp.ack >= req_seq_end and not is_padding_payload(payload):
                # Get inserted request packets with the same service code
                inserted_requests = []
                for inserted_req_idx in range(req_idx+1, len(request_records)):
                    if request_records[inserted_req_idx]["index"] < i and request_records[inserted_req_idx]["cip_service"] == req["cip_service"]:
                        inserted_requests.append(request_records[inserted_req_idx])
                    else:
                        break
                # If there are inserted requests, the response is not valid
                if len(inserted_requests) > 0:
                    continue
                
                # Use pyshark map if available for this response packet
                resp_service = cip_service_map.get(i)
                # Response service code should be request service code ORed with 0x80
                if resp_service is not None and resp_service == (req["cip_service"] | 0x80):
                    indexes_to_keep.add(i)
                    response_records.append(
                        {
                            "index": i,
                            "src": ip.src,
                            "dst": ip.dst,
                            "sport": tcp.sport,
                            "dport": tcp.dport,
                            "seq": tcp.seq,
                            "payload_len": len(payload),
                        }
                    )
                    break
        req_idx += 1

    # Step 4: For each response, search forward for the requestor's ACK confirming the response
    for resp in response_records:
        resp_seq_end = resp["seq"] + resp["payload_len"]
        start_idx = resp["index"] + 1
        end_idx = min(len(packets), start_idx + max_search)
        for i in range(start_idx, end_idx):
            if i in indexes_to_keep:
                continue
            pkt = packets[i]
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)

            # Requestor's ACK to the response (original request direction, no payload)
            if ip.src == resp["dst"] and ip.dst == resp["src"] and tcp.sport == resp["dport"] and tcp.dport == resp["sport"] and tcp.ack == resp_seq_end and is_padding_payload(payload):
                indexes_to_keep.add(i)
                break

    # Step 5: Write out filtered packets (keep only specified packets)
    filtered_packets = [pkt for i, pkt in enumerate(packets) if i in indexes_to_keep]
    wrpcap(output_pcap, filtered_packets)
    print(
        f"Filtered pcap saved to: {output_pcap}, kept {len(indexes_to_keep)} packets out of {len(packets)} total"
    )
    
    
def filter_enip_keep_service_app(input_pcap, output_pcap, service_codes, max_search=500):
    """
    Filter EtherNet/IP packets to KEEP only those with specified service codes and their related response packets.
    This is the opposite of filter_enip_remove_service which removes specified service codes.

    Args:
        input_pcap (str): Input pcap file path
        output_pcap (str): Output pcap file path
        service_codes (list): List of service codes to KEEP
        max_search (int): Maximum packets to search forward for responses
    """
    # Step 1: Get precise CIP service codes from pyshark (using safe version)
    cip_service_map = get_cip_service_map_safe(input_pcap)

    packets = rdpcap(input_pcap)
    indexes_to_keep = set()
    response_records = []

    # Step 2: Identify request packets by consulting the pyshark CIP service map
    request_records = []
    for i, pkt in enumerate(packets):
        if i not in cip_service_map:
            continue
        cip_service = cip_service_map[i]
        if cip_service in service_codes and pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].dport == 44818:  # Requestor's port is 44818
            tcp = pkt[TCP]
            ip = pkt[IP]
            payload_len = len(bytes(tcp.payload))
            indexes_to_keep.add(i)
            request_records.append(
                {
                    "index": i,
                    "src": ip.src,
                    "dst": ip.dst,
                    "sport": tcp.sport,
                    "dport": tcp.dport,
                    "seq": tcp.seq,
                    "payload_len": payload_len,
                    "cip_service": cip_service,
                }
            )

    # Step 3: For each request, search forward to keep ACK and response packets
    req_idx = 0
    for req in request_records:
        req_seq_end = req["seq"] + req["payload_len"]
        start_idx = req["index"] + 1
        end_idx = min(len(packets), start_idx + max_search)
        for i in range(start_idx, end_idx):
            if i in indexes_to_keep:
                continue
            pkt = packets[i]
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)

            # Responder's CIP response packet - find the first valid response
            if ip.src == req["dst"] and ip.dst == req["src"] and tcp.sport == req["dport"] and tcp.dport == req["sport"] and tcp.ack >= req_seq_end and not is_padding_payload(payload):
                # Get inserted request packets with the same service code
                inserted_requests = []
                for inserted_req_idx in range(req_idx+1, len(request_records)):
                    if request_records[inserted_req_idx]["index"] < i and request_records[inserted_req_idx]["cip_service"] == req["cip_service"]:
                        inserted_requests.append(request_records[inserted_req_idx])
                    else:
                        break
                # If there are inserted requests, the response is not valid
                if len(inserted_requests) > 0:
                    continue
                
                # Use pyshark map if available for this response packet
                resp_service = cip_service_map.get(i)
                # Response service code should be request service code ORed with 0x80
                if resp_service is not None and resp_service == (req["cip_service"] | 0x80):
                    indexes_to_keep.add(i)
                    response_records.append(
                        {
                            "index": i,
                            "src": ip.src,
                            "dst": ip.dst,
                            "sport": tcp.sport,
                            "dport": tcp.dport,
                            "seq": tcp.seq,
                            "payload_len": len(payload),
                        }
                    )
                    break
        req_idx += 1

    # Step 4: Write out filtered packets (keep only specified packets)
    filtered_packets = [pkt for i, pkt in enumerate(packets) if i in indexes_to_keep]
    wrpcap(output_pcap, filtered_packets)
    print(
        f"Filtered pcap saved to: {output_pcap}, kept {len(indexes_to_keep)} packets out of {len(packets)} total"
    )


# =============================================================================
# Testing Functions
# =============================================================================


def test_filter_enip(pcap_file=None, service_codes=None):
    """
    Test function for filter_enip functionality.
    Can be run directly from command line or imported.

    Args:
        pcap_file (str): Path to specific pcap file to test. If None, will search dataset directory.
        service_codes (list): List of service codes to filter. Default is [0x01].
    """
    import os

    print("Testing filter_enip functions...")
    print("=" * 50)

    # Set default service codes if not provided
    if service_codes is None:
        service_codes = [0x01]

    # Determine test file
    if pcap_file is None:
        # Search for pcap files in dataset directory
        dataset_dir = "dataset"
        pcap_files = []

        if os.path.exists(dataset_dir):
            for root, dirs, files in os.walk(dataset_dir):
                for file in files:
                    if file.endswith(".pcap"):
                        pcap_files.append(os.path.join(root, file))

        if not pcap_files:
            print("No pcap files found in dataset directory.")
            print("Creating a test with non-existent file to check error handling...")

            try:
                result = get_cip_service_map_safe("non_existent_file.pcap")
                print(f"Result: {result}")
            except Exception as e:
                print(f"Expected error: {e}")
            return

        test_file = pcap_files[0]
        print(f"Using first pcap file found: {test_file}")
    else:
        # Use specified file
        test_file = pcap_file
        if not os.path.exists(test_file):
            print(f"Error: Specified file does not exist: {test_file}")
            return
        print(f"Using specified pcap file: {test_file}")

    print(f"Service codes: {[hex(code) for code in service_codes]}")

    # Test 1: Test get_cip_service_map_safe
    """
    print("\n1. Testing get_cip_service_map_safe...")
    try:
        service_map = get_cip_service_map_safe(test_file)
        print(f"Success! Found {len(service_map)} CIP service mappings")
        if service_map:
            print(f"Sample mappings: {dict(list(service_map.items())[:5])}")
    except Exception as e:
        print(f"Error in get_cip_service_map_safe: {e}")
        return
    """
    
    # Test 2: Test filter_enip_remove_service (REMOVE specified service codes)
    """ 
    print("\n2. Testing filter_enip_remove_service (REMOVE mode)...")
    output_file_remove = test_file.replace(".pcap", "_test_removed.pcap")
    try:
        filter_enip_remove_service(test_file, output_file_remove, service_codes)
        print("Success! Remove filtering completed.")

        # Check if output file was created
        if os.path.exists(output_file_remove):
            print(f"Remove output file created: {output_file_remove}")
            # Clean up test output file
            os.remove(output_file_remove)
            print(f"Cleaned up remove test file: {output_file_remove}")
        else:
            print("Warning: Remove output file was not created")

    except Exception as e:
        print(f"Error in filter_enip_remove_service: {e}")
    """

    # Test 3: Test filter_enip_keep_service (KEEP specified service codes)
    print("\n3. Testing filter_enip_keep_service (KEEP mode)...")
    output_file_keep = test_file.replace(".pcap", "_test_kept_app.pcap")
    try:
        filter_enip_keep_service_app(test_file, output_file_keep, service_codes)
        print("Success! Keep filtering completed.")

        # Check if output file was created
        if os.path.exists(output_file_keep):
            print(f"Keep output file created: {output_file_keep}")
            # Clean up test output file
            # os.remove(output_file_keep)
            # print(f"Cleaned up keep test file: {output_file_keep}")
        else:
            print("Warning: Keep output file was not created")

    except Exception as e:
        print(f"Error in filter_enip_keep_service: {e}")

    print("\n" + "=" * 50)
    print("Testing completed!")


# =============================================================================
# Main Execution
# =============================================================================

if __name__ == "__main__":
    # Run tests when script is executed directly
    # You can modify these parameters to test specific files
    pcap_file = "dataset/swat/Dec2019_00000_20191206100500_00000w_filtered(192.168.1.10-192.168.1.200).pcap"
    service_codes = [0x4C]  # Example service codes to filter

    test_filter_enip(pcap_file, service_codes)

    # Example: Test with specific file and service codes
    # Uncomment and modify the line below to test a specific file:
    # test_filter_enip("dataset/scada/your_specific_file.pcap", [0x01, 0x02])

    # Example: Test with different service codes
    # test_filter_enip("your_file.pcap", [0x01, 0x04, 0x0E])
