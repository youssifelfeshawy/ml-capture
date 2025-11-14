from scapy.all import *
from scapy.interfaces import get_if_list, IFACES
import csv
from collections import defaultdict
import math
from typing import List, Dict
import argparse
import time
import os

# Parse command-line arguments for configurability
parser = argparse.ArgumentParser(
    description="Continuously capture live traffic and extract UNSW-NB15 features to CSV files."
)
parser.add_argument(
    "--iface",
    type=str,
    default="all",
    help="Network interface to capture on (default: eth0). Use 'all' to capture on all interfaces.",
)
parser.add_argument(
    "--capture_duration", type=int, default=60, help="Duration of each capture in seconds (default: 60)"
)
parser.add_argument(
    "--output_dir",
    type=str,
    default="/tmp/captures",
    help="Output directory for CSV files (default: /tmp/captures)",
)
args = parser.parse_args()

# Create output directory if it doesn't exist
os.makedirs(args.output_dir, exist_ok=True)

# Determine interface(s)
if args.iface == 'all':
    all_ifaces = get_if_list()
    iface = [ifname for ifname in all_ifaces if IFACES.dev_from_name(ifname).flags & 1]  # UP interfaces
else:
    iface = args.iface

# Function to get flow key and direction
def get_flow_key(pkt):
    if IP not in pkt:
        return None, None
    ip = pkt[IP]
    proto_num = ip.proto
    src_ip = ip.src
    dst_ip = ip.dst
    if proto_num == 6:  # TCP
        if TCP not in pkt:
            return None, None
        proto_str = "tcp"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif proto_num == 17:  # UDP
        if UDP not in pkt:
            return None, None
        proto_str = "udp"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif proto_num == 1:  # ICMP
        proto_str = "icmp"
        src_port = 0
        dst_port = 0
    else:
        return None, None
    # Bidirectional key: sort by IP and port
    if (src_ip, src_port) < (dst_ip, dst_port):
        key = (src_ip, src_port, dst_ip, dst_port, proto_str)
        is_forward = True
    else:
        key = (dst_ip, dst_port, src_ip, src_port, proto_str)
        is_forward = False
    return key, is_forward

# Main loop for continuous capture
while True:
    try:
        # Generate timestamped output filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_csv = os.path.join(args.output_dir, f"capture_{timestamp}.csv")
        
        print(f"Starting capture on interface(s): {iface} for {args.capture_duration} seconds...")
        packets = sniff(iface=iface, timeout=args.capture_duration)
        print(f"Capture complete. Processing {len(packets)} packets...")

        # Group packets into flows
        flows = defaultdict(list)
        for pkt in packets:
            key, is_forward = get_flow_key(pkt)
            if key:
                flows[key].append((pkt.time, pkt, is_forward))

        # Prepare list of flow data
        flows_data: List[Dict] = []

        for key, pkt_list in flows.items():
            if not pkt_list:
                continue
            # Sort packets by time
            pkt_list.sort(key=lambda x: x[0])
            first_time = pkt_list[0][0]
            last_time = pkt_list[-1][0]
            dur = max(last_time - first_time, 0.000001)  # Avoid division by zero

            proto = key[4]
            src = key[0]
            sport = key[1]
            dst = key[2]
            dport = key[3]

            # Expanded service map based on common ports
            port_to_service = {
                80: "http",
                443: "https",
                53: "dns",
                22: "ssh",
                21: "ftp",
                25: "smtp",
                110: "pop3",
                6667: "irc",
                161: "snmp",
                1812: "radius",
                20: "ftp-data",  # Add more as needed
            }
            service_port = min(sport, dport) if sport != dport else sport
            service = port_to_service.get(service_port, "-")

            # Expanded state (approximate)
            state = "INT"
            flags_set = set()
            for _, pkt, _ in pkt_list:
                if proto == "tcp" and TCP in pkt:
                    flags_set.update(str(pkt[TCP].flags))
            if proto == "tcp":
                if "F" in flags_set:
                    state = "FIN"
                elif "S" in flags_set and "A" in flags_set:
                    state = "CON"
                elif "R" in flags_set:
                    state = "RST"
                # Add more if needed, e.g., if only 'S': state = 'REQ'
            elif proto == "udp":
                state = (
                    "CON"
                    if sum(1 for _, _, f in pkt_list if f) > 0
                    and sum(1 for _, _, f in pkt_list if not f) > 0
                    else "INT"
                )
            elif proto == "icmp":
                state = "no"  # Or 'INT'

            # Packet and byte counts
            spkts = sum(1 for _, _, f in pkt_list if f)
            sbytes = sum(len(pkt) for _, pkt, f in pkt_list if f)
            dbytes = sum(len(pkt) for _, pkt, f in pkt_list if not f)

            # Loads (with rate rounding)
            sload = (sbytes * 8) / dur if dur > 0 else 0
            dload = (dbytes * 8) / dur if dur > 0 else 0

            # Inter-arrival times and jitter (with std dev in ms)
            src_times = [t for t, _, f in pkt_list if f]
            dst_times = [t for t, _, f in pkt_list if not f]
            sintpkt = 0
            sjit = 0
            if len(src_times) > 1:
                src_iats = [src_times[i + 1] - src_times[i] for i in range(len(src_times) - 1)]
                mean_iat = sum(src_iats) / len(src_iats)
                sintpkt = mean_iat * 1000  # ms
                if len(src_iats) > 1:
                    variance = sum((x - mean_iat) ** 2 for x in src_iats) / (len(src_iats) - 1)
                else:
                    variance = 0
                sjit = math.sqrt(variance) * 1000  # Std dev in ms
            dintpkt = 0
            djit = 0
            if len(dst_times) > 1:
                dst_iats = [dst_times[i + 1] - dst_times[i] for i in range(len(dst_times) - 1)]
                mean_iat = sum(dst_iats) / len(dst_iats)
                dintpkt = mean_iat * 1000  # ms
                if len(dst_iats) > 1:
                    variance = sum((x - mean_iat) ** 2 for x in dst_iats) / (len(dst_iats) - 1)
                else:
                    variance = 0
                djit = math.sqrt(variance) * 1000  # Std dev in ms

            # Window sizes (max)
            src_wins = [
                pkt[TCP].window for _, pkt, f in pkt_list if proto == "tcp" and TCP in pkt and f
            ]
            swin = max(src_wins) if src_wins else 0

            # TCP base sequences
            stcpb = next(
                (pkt[TCP].seq for _, pkt, f in pkt_list if proto == "tcp" and TCP in pkt and f),
                0,
            )
            dtcpb = next(
                (
                    pkt[TCP].seq
                    for _, pkt, f in pkt_list
                    if proto == "tcp" and TCP in pkt and not f
                ),
                0,
            )

            # TCP RTT, synack, ackdat
            tcprtt = 0
            synack = 0
            ackdat = 0
            if proto == "tcp":
                syn_time = None
                synack_time = None
                ack_time = None
                for t, pkt, f in pkt_list:
                    if TCP in pkt:
                        flags = pkt[TCP].flags
                        if flags.S and not flags.A and f:  # SYN
                            syn_time = t
                        elif flags.S and flags.A and not f:  # SYN-ACK
                            synack_time = t
                        elif flags.A and not flags.S and f and synack_time:  # ACK after SYN-ACK
                            ack_time = t
                            break
                if syn_time and synack_time:
                    synack = synack_time - syn_time
                if synack_time and ack_time:
                    ackdat = ack_time - synack_time
                tcprtt = synack + ackdat

            # Mean packet sizes
            smeansz = sbytes / spkts if spkts > 0 else 0
            dmeansz = (
                dbytes / (spkts + len(dst_times)) if len(dst_times) > 0 else 0
            )  # Adjusted since dpkts removed, but dmeansz uses dpkts

            # HTTP and FTP features (basic parsing)
            trans_depth = 0
            res_bdy_len = 0

            if service == "http":
                try:
                    load_layer("http")
                except:
                    pass
                else:
                    for _, pkt, f in pkt_list:
                        if HTTPResponse in pkt and not f:
                            if pkt.haslayer(Raw):
                                res_bdy_len += len(pkt[Raw].load)
                trans_depth = 0  # Approximate, since ct_flw_http_mthd removed

            # is_sm_ips_ports
            is_sm_ips_ports = 1 if src == dst and sport == dport else 0

            # TTL values
            src_ttls = [pkt[IP].ttl for _, pkt, f in pkt_list if IP in pkt and f]
            dst_ttls = [pkt[IP].ttl for _, pkt, f in pkt_list if IP in pkt and not f]
            sttl = max(src_ttls) if src_ttls else 0
            dttl = max(dst_ttls) if dst_ttls else 0

            # Partial row without aggregate features
            row = {
                "src_ip": src,
                "dst_ip": dst,
                "proto": proto,
                "state": state,
                "dur": dur,
                "sbytes": sbytes,
                "dbytes": dbytes,
                "sttl": sttl,
                "dttl": dttl,
                "service": service,
                "sload": sload,
                "dload": dload,
                "spkts": spkts,
                "swin": swin,
                "stcpb": stcpb,
                "dtcpb": dtcpb,
                "smeansz": smeansz,
                "dmeansz": dmeansz,
                "trans_depth": trans_depth,
                "res_bdy_len": res_bdy_len,
                "sjit": sjit,
                "djit": djit,
                "sintpkt": sintpkt,
                "dintpkt": dintpkt,
                "tcprtt": tcprtt,
                "synack": synack,
                "ackdat": ackdat,
                "is_sm_ips_ports": is_sm_ips_ports,
            }

            flows_data.append(
                {
                    "row": row,
                    "last_time": last_time,
                    "src_ip": src,
                    "dst_ip": dst,
                    "sport": sport,
                    "dport": dport,
                    "service": service,
                    "state": state,
                    "sttl": sttl,
                    "dttl": dttl,
                }
            )

        # Sort flows_data by last_time
        flows_data.sort(key=lambda x: x["last_time"])

        # Compute aggregate features
        for i, flow in enumerate(flows_data):
            start_idx = max(0, i - 99)
            window = flows_data[start_idx : i + 1]

            # ct_srv_src: connections with same src_ip and service
            ct_srv_src = sum(
                1
                for w in window
                if w["src_ip"] == flow["src_ip"] and w["service"] == flow["service"]
            )

            # ct_state_ttl: connections with same state, sttl, dttl
            ct_state_ttl = sum(
                1
                for w in window
                if w["state"] == flow["state"]
                and w["sttl"] == flow["sttl"]
                and w["dttl"] == flow["dttl"]
            )

            # ct_dst_ltm: connections with same dst_ip
            ct_dst_ltm = sum(1 for w in window if w["dst_ip"] == flow["dst_ip"])

            # ct_dst_sport_ltm: connections with same dst_ip and sport
            ct_dst_sport_ltm = sum(
                1
                for w in window
                if w["dst_ip"] == flow["dst_ip"] and w["sport"] == flow["sport"]
            )

            # ct_src_ltm: connections with same src_ip
            ct_src_ltm = sum(1 for w in window if w["src_ip"] == flow["src_ip"])

            flow["row"]["ct_state_ttl"] = ct_state_ttl
            flow["row"]["ct_srv_src"] = ct_srv_src
            flow["row"]["ct_dst_ltm"] = ct_dst_ltm
            flow["row"]["ct_src_ltm"] = ct_src_ltm
            flow["row"]["ct_dst_sport_ltm"] = ct_dst_sport_ltm

        # Prepare CSV
        with open(output_csv, "w", newline="") as csvfile:
            fieldnames = [
                "src_ip",
                "dst_ip",
                "proto",
                "state",
                "dur",
                "sbytes",
                "dbytes",
                "sttl",
                "dttl",
                "service",
                "sload",
                "dload",
                "spkts",
                "swin",
                "stcpb",
                "dtcpb",
                "smeansz",
                "dmeansz",
                "trans_depth",
                "res_bdy_len",
                "sjit",
                "djit",
                "sintpkt",
                "dintpkt",
                "tcprtt",
                "synack",
                "ackdat",
                "is_sm_ips_ports",
                "ct_state_ttl",
                "ct_srv_src",
                "ct_dst_ltm",
                "ct_src_ltm",
                "ct_dst_sport_ltm",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for flow in flows_data:
                writer.writerow(flow["row"])

        print(f"CSV file generated: {output_csv}")

        # Optional: Short sleep between captures to avoid high CPU, adjust as needed
        # time.sleep(1)
        
    except Exception as e:
        print(f"Error during capture/processing: {e}")
        # Continue looping even on error
        time.sleep(5)  # Backoff before retry

