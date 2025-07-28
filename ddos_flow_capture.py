import pyshark
import argparse
import csv
import time
import math
import signal
import shutil
import os
from pwn import *
from collections import defaultdict



# Dataset columns
COLUMNS = {
    'Source IP': '',
    'Source Port': '',
    'Destination IP': '',
    'Destination Port': '',
    'Protocol': '',
    'Timestamp': '',
    'Flow Duration': '',
    'Total Fwd Packets': '',
    'Total Backward Packets': '',
    'Total Length of Fwd Packets': '',
    'Total Length of Bwd Packets': '',
    'Fwd Packet Length Max': '',
    'Fwd Packet Length Min': '',
    'Fwd Packet Length Mean': '',
    'Fwd Packet Length Std': '',
    'Bwd Packet Length Max': '',
    'Bwd Packet Length Min': '',
    'Bwd Packet Length Mean': '',
    'Bwd Packet Length Std': '',
    'Flow Bytes/s': '',
    'Flow Packets/s': '',
    'Flow IAT Mean': '',
    'Flow IAT Std': '',
    'Flow IAT Max': '',
    'Flow IAT Min': '',
    'Fwd IAT Total': '',
    'Fwd IAT Mean': '',
    'Fwd IAT Std': '',
    'Fwd IAT Max': '',
    'Fwd IAT Min': '',
    'Bwd IAT Total': '',
    'Bwd IAT Mean': '',
    'Bwd IAT Std': '',
    'Bwd IAT Max': '',
    'Bwd IAT Min': '',
    'Fwd PSH Flags': '',
    'Fwd Header Length': '',
    'Bwd Header Length': '',
    'Fwd Packets/s': '',
    'Bwd Packets/s': '',
    'Min Packet Length': '',
    'Max Packet Length': '',
    'Packet Length Mean': '',
    'Packet Length Std': '',
    'Packet Length Variance': '',
    'FIN Flag Count': '',
    'SYN Flag Count': '',
    'RST Flag Count': '',
    'PSH Flag Count': '',
    'ACK Flag Count': '',
    'URG Flag Count': '',
    'ECE Flag Count': '',
    'Down/Up Ratio': '',
    'Average Packet Size': '',
    'Avg Fwd Segment Size': '',
    'Avg Bwd Segment Size': '',
    'Fwd Header Length.1': '',
    'Subflow Fwd Packets': '',
    'Subflow Fwd Bytes': '',
    'Subflow Bwd Packets': '',
    'Subflow Bwd Bytes': '',
    'Init_Win_bytes_forward': '',
    'Init_Win_bytes_backward': '',
    'act_data_pkt_fwd': '',
    'min_seg_size_forward': '',
    'Active Mean': '',
    'Active Std': '',
    'Active Max': '',
    'Active Min': '',
    'Idle Mean': '',
    'Idle Std': '',
    'Idle Max': '',
    'Idle Min': '',
    'Label': '',
}


# Dictionary to store active flows
flows = {}

# Gets the packet and returns a tuple
def get_flow_key(pkt):  # 4.1
    try:
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst

        protocol = pkt.transport_layer if hasattr(pkt, 'transport_layer') else pkt.highest_layer

        # Intenta obtener los puertos, usa 0 si no existen
        try:
            src_port = pkt[pkt.transport_layer].srcport
        except:
            src_port = '0'

        try:
            dst_port = pkt[pkt.transport_layer].dstport
        except:
            dst_port = '0'

        return (src_ip, dst_ip, src_port, dst_port, protocol)
    except:
        return None

# Initial function, calls the rest of the functions
def process_packet(pkt): # 4
    principal_cols(pkt)
    min_seg_size_fwd(pkt)
    bwd_cols(pkt)
    fwd_cols(pkt)
    packets_count(pkt)
    flags_count(pkt)

# Gets basic flow information
def principal_cols(pkt):
    global flow, length
    key = get_flow_key(pkt) # 4.1
    if not key:
        return

    now = float(pkt.sniff_timestamp)
    length = int(pkt.length)

    if key not in flows:
        flows[key] = {
            'start_time': now,
            'end_time': now,
            'last_seen': now,
            'packet_lengths': [],
            'urg_count': 0,
            'fwd_lengths': [],
            'min_packet_len': length,
            'max_packet_len': length,
            'src_ip': pkt.ip.src,
            'dst_ip': pkt.ip.dst,
            'src_port': key[2],
            'dst_port': key[3],
            'protocol': key[4]
        }

    flow = flows[key]

    timestamp = int(time.time())
    flow['timestamp'] = timestamp

    flow['fwd_lengths'].append(length)
    flow['end_time'] = now
    flow['last_seen'] = now
    flow['packet_lengths'].append(length)
    flow['min_packet_len'] = min(flow['min_packet_len'], length)
    flow['max_packet_len'] = max(flow['max_packet_len'], length)
    flow['avg_fwd_segment_size'] = sum(flow['fwd_lengths'])/len(flow['fwd_lengths'])

    
    lengths = flow['packet_lengths']
    if lengths:
        mean = sum(lengths) / len(lengths)
        variance = sum((x - mean) ** 2 for x in lengths) / len(lengths)
        flow['Packet Length Mean'] = mean
        flow['Packet Length Variance'] = variance
        flow['Packet Length Std'] = variance ** 0.5
        flow['Average Packet Size'] = mean


# Calculates the min_seg_size_fwd column
def min_seg_size_fwd(pkt):
    try:
        ip_header_len = int(pkt.ip.hdr_len)
        tcp_header_len = int(pkt.tcp.hdr_len)
        total_length = int(pkt.length)
        seg_size = total_length - ip_header_len - tcp_header_len

        if 'min_seg_size_fwd' not in flow:
            flow['min_seg_size_fwd'] = seg_size
        else:
            flow['min_seg_size_fwd'] = min(flow['min_seg_size_fwd'], seg_size)
    except:
        pass

# Calculates columns related to BWD packets
def bwd_cols(pkt):
    bwd_lengths = flow.setdefault('bwd_lengths', [])
    bwd_lengths.append(length)

    if bwd_lengths:
        bwd_mean = sum(bwd_lengths) / len(bwd_lengths)
        variance = sum((x - bwd_mean) ** 2 for x in bwd_lengths) / len(bwd_lengths)
        flow['bwd_packet_length_mean'] = bwd_mean
        flow['bwd_packet_length_std'] = math.sqrt(variance)
        flow['avg_bwd_segment_size'] = bwd_mean
        flow['bwd_packet_length_max'] = max(bwd_lengths)


# Calculates columns related to FWD packets
def fwd_cols(pkt):
    fwd_lengths = flow['fwd_lengths']
    if fwd_lengths:
        fwd_mean = sum(fwd_lengths) / len(fwd_lengths)
        variance = sum((x - fwd_mean) ** 2 for x in fwd_lengths) / len(fwd_lengths)
        flow['fwd_packet_length_mean'] = sum(fwd_lengths) / len(fwd_lengths)
        flow['fwd_packet_length_std'] = math.sqrt(variance)
        flow['avg_fwd_segment_size'] = fwd_mean
        flow['fwd_packet_length_max'] = max(fwd_lengths)
        flow['fwd_packet_length_min'] = min(fwd_lengths)

    if 'bwd_packet_len_min' not in flow:
        flow['bwd_packet_len_min'] = length
    else:
        flow['bwd_packet_len_min'] = min(flow['bwd_packet_len_min'], length)

    if 'fwd_packet_len_min' not in flow:
        flow['fwd_packet_len_min'] = length
    else:
        flow['fwd_packet_len_min'] = min(flow['fwd_packet_len_min'], length)

# Packet, Bytes, Header counters...
def packets_count(pkt):
    total_fwd_packets = 0
    total_bwd_packets = 0

    total_fwd_length = 0
    total_bwd_length = 0

    total_fwd_hdr_len = 0
    total_bwd_hdr_len = 0


    for key, flow_packets in flows.items():
        src_ip, dst_ip, src_port, dst_port, protocol = key
        try:
            if pkt.ip.src == src_ip and pkt.ip.dst == dst_ip:
                total_fwd_packets += 1 # Número de paquetes
                total_fwd_length += int(pkt.length) # Número de Bytes
                tcp_hdr_len = int(pkt.tcp.hdr_len) if hasattr(pkt.tcp, 'hdr_len') else 0 # Bytes en cabecera
                total_fwd_hdr_len += tcp_hdr_len # Bytes en cabecera

            elif pkt.ip.src == dst_ip and pkt.ip.dst == src_ip:
                total_bwd_packets += 1 # Número de paquetes
                total_bwd_length += int(pkt.length) # Número de Bytes
                tcp_hdr_len = int(pkt.tcp.hdr_len) if hasattr(pkt.tcp, 'hdr_len') else 0 # Bytes en cabecera
                total_bwd_hdr_len += tcp_hdr_len # Bytes en cabecera

        except AttributeError:
            continue

   


    flow['Total Fwd Packets'] = total_fwd_packets
    flow['Total Backward Packets'] = total_bwd_packets

    flow['Total Length of Fwd Packets'] = total_fwd_length
    flow['Total Length of Bwd Packets'] = total_bwd_length

    flow['Fwd Header Length'] = total_fwd_hdr_len
    flow['Bwd Header Length'] = total_bwd_hdr_len

# Flag counter and their types
def flags_count(pkt):
    global flags
    flags = {
        'SYN Flag Count': 0,
        'ACK Flag Count': 0,
        'RST Flag Count': 0,
        'PSH Flag Count': 0,
        'URG Flag Count': 0,
        'FIN Flag Count': 0,
        'ECE Flag Count': 0
    }
    try:
        flags_hex = pkt.tcp.flags
        flags_int = int(flags_hex, 16)
        flags_bin = format(flags_int, '08b')

        if flags_bin[1] == '1': flags['ECE Flag Count'] += 1
        if flags_bin[2] == '1': flags['URG Flag Count'] += 1
        if flags_bin[3] == '1': flags['ACK Flag Count'] += 1
        if flags_bin[4] == '1': flags['PSH Flag Count'] += 1
        if flags_bin[5] == '1': flags['RST Flag Count'] += 1
        if flags_bin[6] == '1': flags['SYN Flag Count'] += 1
        if flags_bin[7] == '1': flags['FIN Flag Count'] += 1
    except Exception as e:
        pass
    

# Converts protocol from text to number
def convert_protocol(protocol): 
    if protocol == "TCP":
        new_protocol = 6
    elif protocol == "UDP":
        new_protocol = 17
    else:
        new_protocol = 0
    return new_protocol

# Exports each flow
def export_flow(flow): # 6
    row = COLUMNS.copy()


    row['Timestamp'] = flow.get('timestamp', '')

    row['Flow Duration'] = (flow.get('end_time', '0') - flow.get('start_time', '0')) * 1_000_000
    row['Destination Port'] = flow.get('dst_port', '')
    row['Source Port'] = flow.get('src_port', '')

    row['Protocol'] = convert_protocol(flow.get('protocol', ''))
    row['Destination IP'] = flow.get('dst_ip', '')
    row['Source IP'] = flow.get('src_ip', '')

    row['URG Flag Count'] = flags.get('URG Flag Count', '')
    row['ACK Flag Count'] = flags.get('ACK Flag Count', '')
    row['PSH Flag Count'] = flags.get('PSH Flag Count', '')
    row['RST Flag Count'] = flags.get('RST Flag Count', '')
    row['SYN Flag Count'] = flags.get('SYN Flag Count', '')
    row['FIN Flag Count'] = flags.get('FIN Flag Count', '')
    row['ECE Flag Count'] = flags.get('ECE Flag Count', '')


    row['Min Packet Length'] = flow.get('min_packet_len', '')
    row['Max Packet Length'] = flow.get('max_packet_len', '')
    row['Avg Fwd Segment Size'] = flow.get('avg_fwd_segment_size', '')
    row['min_seg_size_forward'] = flow.get('min_seg_size_fwd', '')
    row['Bwd Packet Length Min'] = flow.get('bwd_packet_len_min', '')
    row['Fwd Packet Length Min'] = flow.get('fwd_packet_len_min', '')

    row['Bwd Packet Length Mean'] = flow.get('bwd_packet_length_mean', '')
    row['Bwd Packet Length Std'] = flow.get('bwd_packet_length_std', '')
    row['Avg Bwd Segment Size'] = flow.get('avg_bwd_segment_size', '')
    row['Bwd Packet Length Max'] = flow.get('bwd_packet_length_max', '')

    row['Fwd Packet Length Mean'] = flow.get('fwd_packet_length_mean', '')
    row['Fwd Packet Length Std'] = flow.get('fwd_packet_length_std', '')
    row['Avg Fwd Segment Size'] = flow.get('avg_fwd_segment_size', '')
    row['Fwd Packet Length Max'] = flow.get('fwd_packet_length_max', '')

    row['Total Backward Packets'] = flow.get('Total Backward Packets', '')
    row['Total Fwd Packets'] = flow.get('Total Fwd Packets', '')

    row['Packet Length Mean'] = flow.get('Packet Length Mean', '')
    row['Packet Length Variance'] = flow.get('Packet Length Variance', '')
    row['Packet Length Std'] = flow.get('Packet Length Std', '')
    row['Average Packet Size'] = flow.get('Average Packet Size', '')

    row['Total Length of Fwd Packets'] = flow.get('Total Length of Fwd Packets', '')
    row['Total Length of Bwd Packets'] = flow.get('Total Length of Bwd Packets', '')

    row['Fwd Header Length'] = flow.get('Fwd Header Length', '')
    row['Bwd Header Length'] = flow.get('Bwd Header Length', '')



# Checks for expired flows and exports them
    with open(OUTPUT_CSV, mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=COLUMNS.keys())
        writer.writerow(row)

def check_expired_flows(): # 5
    now = time.time()
    expired = [k for k, v in flows.items() if now - v['last_seen'] > FLOW_TIMEOUT]
    for k in expired:
        export_flow(flows[k]) # 6
        del flows[k]

def move_file():
# Moves the generated CSV to destination directory
    destino = "/opt/DDOS/generated/"
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    shutil.move(OUTPUT_CSV, destino)

def start_capture(): # 3
    capture = pyshark.LiveCapture(interface=INTERFACE, display_filter='ip')
    packet_count = 0
    tiempo_inicio = time.time()
    packet_count_log = log.progress("Number of captured packets")
    tiempo_log = log.progress("Execution time")

    try:
        for pkt in capture.sniff_continuously():
            packet_count += 1
            packet_count_log.status(packet_count)

            elapsed = time.time() - tiempo_inicio
            hours, remainder = divmod(int(elapsed), 3600)
            minutes, seconds = divmod(remainder, 60)
            tiempo_formateado = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            tiempo_log.status(tiempo_formateado)

            process_packet(pkt) # 4
            check_expired_flows() # 5

            if packet_count == 5000:
                print(f"Generating file {OUTPUT_CSV}")
                for flow in flows.values():
                    export_flow(flow) # 6
                move_file() # Creates the necessary directories and CSV structure
                main() # Main function
            
    except KeyboardInterrupt:
        print(f"Ending capture. Exporting remaining flows...")
        for flow in flows.values():
            export_flow(flow) # 6
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        try:
            capture.close()
            if hasattr(capture, 'eventloop') and capture.eventloop.is_running():
                capture.eventloop.stop()
        except Exception as e:
            print(f"Error closing the capture: {e}")
        print("Program finished")

def create_csv(): # 2
    global OUTPUT_CSV, FLOW_TIMEOUT

    base_path = "/opt/DDOS"
    subfolders = ["generated", "read", "scanning"]
    try:
        os.makedirs(base_path, exist_ok=True)

        for folder in subfolders:
            path = os.path.join(base_path, folder)
            os.makedirs(path, exist_ok=True)
    except PermissionError:
        print("Permission denied. Run this script with superuser privileges (sudo)")

    timestamp = int(time.time())
    filename = f"{timestamp}_scan.csv"
    output_dir = "/opt/DDOS/scanning"
    OUTPUT_CSV = os.path.join(output_dir, filename)
    FLOW_TIMEOUT = 60 

    # Create CSV file
    with open(OUTPUT_CSV, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=COLUMNS.keys())
        writer.writeheader()
    start_capture()
    


def main(): # 1
    global INTERFACE
    parser = argparse.ArgumentParser(description="Network Traffic Detector for DDoS Attacks")
    parser.add_argument("-i", "--interface", required=True, help="Network interface name (e.g., eth0, wlan0)")
    
    args = parser.parse_args()
    INTERFACE = args.interface

    print(f"\n[*] Capturing traffic on interface: {INTERFACE}")
    create_csv()




if __name__ == "__main__":
    main()
