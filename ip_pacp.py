from scapy.all import rdpcap
import sys

def display_ip_and_protocol(pcap_file, filter_protocol=None):
    packets = rdpcap(pcap_file)

    ip_info = {}  # Dictionary to store IP addresses and their associated protocols
    protocol_names = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        22: "SSH",
        21: "FTP"
    }

    for packet in packets:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            protocol = packet["IP"].proto

            if filter_protocol is not None and filter_protocol != "ALL" and str(protocol) != filter_protocol:
                continue

            ip_info[src_ip] = protocol_names.get(protocol, "Unknown")
            ip_info[dst_ip] = protocol_names.get(protocol, "Unknown")

    return ip_info

def export_to_text_file(data, output_file=None):
    if output_file:
        with open(output_file, "w") as file:
            for ip, protocol in data.items():
                file.write(f"IP: {ip} | Protocol: {protocol}\n")
    else:
        for ip, protocol in data.items():
            print(f"IP: {ip} | Protocol: {protocol}")

def get_protocol_option():
    print("Which protocol would you like to filter by?")
    print("Options: [All], [ICMP], [TCP], [UDP], [DNS], [HTTP], [HTTPS], [SMTP], [POP3], [IMAP], [SSH], [FTP]")
    protocol_option = input("Enter the protocol option (e.g., All, TCP): ").upper()

    protocol_mapping = {
        "ALL": "ALL",
        "ICMP": "1",
        "TCP": "6",
        "UDP": "17",
        "DNS": "53",
        "HTTP": "80",
        "HTTPS": "443",
        "SMTP": "25",
        "POP3": "110",
        "IMAP": "143",
        "SSH": "22",
        "FTP": "21",
    }

    return protocol_mapping.get(protocol_option)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pcap_ip_protocol_export.py [PCAP_FILE] [-o OUTPUT_FILE]")
        sys.exit(1)

    pcap_file = sys.argv[1]
    filter_protocol = None

    output_file = None
    if "-o" in sys.argv:
        index = sys.argv.index("-o")
        if index < len(sys.argv) - 1:
            output_file = sys.argv[index + 1]

    filter_protocol = get_protocol_option()

    ip_info = display_ip_and_protocol(pcap_file, filter_protocol)

    if not ip_info:
        print("No IP addresses and protocols found in the PCAP file.")
    else:
        export_to_text_file(ip_info, output_file)
        if output_file:
            print(f"Data exported to {output_file}")
