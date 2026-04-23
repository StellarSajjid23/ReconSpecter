#!/usr/bin/env python3

import sys
import time
import socket
import ipaddress
from collections import Counter, defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from colorama import init as colorama_init
    colorama_init()
except ImportError:
    pass


# =========================
# COLORS
# =========================
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# =========================
# CONFIG
# =========================
COMMON_SUSPICIOUS_PORTS = {
    21, 23, 69, 135, 137, 138, 139, 445, 1433, 1521, 2375, 3306,
    3389, 4444, 5432, 5900, 6379, 8080, 8443, 9200, 27017
}

WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000}
PRIVATE_RANGES_NOTE = "Private/Internal"


# =========================
# OUTPUT HELPERS
# =========================
def print_message(message: str):
    print(message + Colors.RESET)


def ask_input(prompt: str) -> str:
    return input(Colors.YELLOW + prompt + Colors.RESET)


# =========================
# BANNER
# =========================
def print_banner():
    banner = r"""
        +----------------------------------------------------------------------------------------------+
        |       ___                 _             _       ___                                          |
        |      (  _`\              ( )           ( )_    |  _`\                                        |
        |      | |_) )  _ _    ___ | |/')    __  | ,_)   | (_) )   __     _ _  _ _      __   _ __      |
        |      | ,__/'/'_` ) /'___)| , <   /'__`\| |     | ,  /  /'__`\ /'_` )( '_`\  /'__`\( '__)     |
        |      | |   ( (_| |( (___ | |\`\ (  ___/| |_    | |\ \ (  ___/( (_| || (_) )(  ___/| |        |
        |      (_)   `\__,_)`\____)(_) (_)`\____)`\__)   (_) (_)`\____)`\__,_)| ,__/'`\____)(_)        |
        |                                                                     | |                      |
        |                                                                     (_)                      |
        +----------------------------------------------------------------------------------------------+
        |                            Live Traffic Intelligence Console                                 |
        +----------------------------------------------------------------------------------------------+
"""
    print(Colors.RED + banner + Colors.RESET)
    print(Colors.CYAN + "[*] Internship Portfolio Edition" + Colors.RESET)
    print(Colors.GREEN + "[*] Author: StellarSajjid23" + Colors.RESET)
    print(Colors.YELLOW + "[*] Engine: Advanced Packet Visibility and Triage" + Colors.RESET)
    print("                                                                       ")


# =========================
# NETWORK HELPERS
# =========================
def get_local_ipv4_addresses() -> set:
    ips = set()
    try:
        hostname = socket.gethostname()
        for result in socket.getaddrinfo(hostname, None, socket.AF_INET):
            if result[4] and result[4][0]:
                ips.add(result[4][0])
    except Exception:
        pass

    ips.add("127.0.0.1")
    return ips


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global
    except ValueError:
        return False


def classify_ip_type(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return "Private"
        if ip_obj.is_loopback:
            return "Loopback"
        if ip_obj.is_multicast:
            return "Multicast"
        if ip_obj.is_reserved:
            return "Reserved"
        if ip_obj.is_global:
            return "Public"
        return "Unknown"
    except ValueError:
        return "Invalid"


def get_geoip(ip: str) -> dict:
    result = {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "note": "Unavailable"
    }

    if not is_public_ip(ip):
        result["note"] = PRIVATE_RANGES_NOTE
        return result

    if not REQUESTS_AVAILABLE:
        result["note"] = "requests missing"
        return result

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
        data = response.json()

        if data.get("status") == "success":
            result["country"] = data.get("country", "Unknown")
            result["city"] = data.get("city", "Unknown")
            result["isp"] = data.get("isp", "Unknown")
            result["note"] = "Success"
        else:
            result["note"] = "Lookup Failed"
    except Exception:
        result["note"] = "Lookup Failed"

    return result


def get_direction(src_ip: str, dst_ip: str, local_ips: set) -> str:
    if src_ip in local_ips and dst_ip in local_ips:
        return "Local"
    if src_ip in local_ips:
        return "Outbound"
    if dst_ip in local_ips:
        return "Inbound"
    return "Transit/Unknown"


# =========================
# PACKET PARSING
# =========================
def get_protocol_name(packet) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def tcp_flag_string(flags) -> str:
    names = []
    if flags & 0x01:
        names.append("FIN")
    if flags & 0x02:
        names.append("SYN")
    if flags & 0x04:
        names.append("RST")
    if flags & 0x08:
        names.append("PSH")
    if flags & 0x10:
        names.append("ACK")
    if flags & 0x20:
        names.append("URG")
    if flags & 0x40:
        names.append("ECE")
    if flags & 0x80:
        names.append("CWR")
    return ",".join(names) if names else "-"


def extract_dns_query(packet) -> str:
    try:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname
            if isinstance(qname, bytes):
                return qname.decode(errors="ignore").rstrip(".")
            return str(qname).rstrip(".")
    except Exception:
        pass
    return "-"


def extract_http_host(packet) -> str:
    try:
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw]).decode(errors="ignore")
            lines = payload.splitlines()
            for line in lines:
                if line.lower().startswith("host:"):
                    return line.split(":", 1)[1].strip()[:40]
    except Exception:
        pass
    return "-"


def classify_port_risk(src_port: str, dst_port: str) -> str:
    ports = []
    for value in [src_port, dst_port]:
        if str(value).isdigit():
            ports.append(int(value))

    if any(port in COMMON_SUSPICIOUS_PORTS for port in ports):
        return "High"

    if any(port in WEB_PORTS for port in ports):
        return "Medium"

    return "Low"


def extract_packet_info(packet: object, local_ips: set) -> dict:
    info = {
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "protocol": "OTHER",
        "src_port": "-",
        "dst_port": "-",
        "length": len(packet),
        "direction": "Transit/Unknown",
        "tcp_flags": "-",
        "dns_query": "-",
        "http_host": "-",
        "risk": "Low",
        "timestamp": time.strftime("%H:%M:%S")
    }

    if packet.haslayer(IP):
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst
        info["direction"] = get_direction(info["src_ip"], info["dst_ip"], local_ips)

    if packet.haslayer(TCP):
        info["protocol"] = "TCP"
        info["src_port"] = str(packet[TCP].sport)
        info["dst_port"] = str(packet[TCP].dport)
        info["tcp_flags"] = tcp_flag_string(int(packet[TCP].flags))

    elif packet.haslayer(UDP):
        info["protocol"] = "UDP"
        info["src_port"] = str(packet[UDP].sport)
        info["dst_port"] = str(packet[UDP].dport)

    elif packet.haslayer(ICMP):
        info["protocol"] = "ICMP"

    info["dns_query"] = extract_dns_query(packet)
    info["http_host"] = extract_http_host(packet)
    info["risk"] = classify_port_risk(info["src_port"], info["dst_port"])

    return info


# =========================
# ANALYSIS ENGINE
# =========================
def choose_capture_mode() -> dict:
    print(Colors.CYAN + "Choose Capture Mode:" + Colors.RESET)
    print(Colors.WHITE + "1. Packet Count Mode" + Colors.RESET)
    print(Colors.WHITE + "2. Timed Capture Mode\n" + Colors.RESET)

    choice = ask_input("Enter Choice [ 1 / 2 ] : ").strip()

    if choice == "2":
        seconds_input = ask_input("Enter Capture Duration in Seconds [ Default 15 ] : ").strip()
        seconds = 15
        if seconds_input.isdigit() and int(seconds_input) > 0:
            seconds = int(seconds_input)
        return {"mode": "time", "seconds": seconds}

    packet_input = ask_input("Enter Number of Packets to Capture [ Default 25 ] : ").strip()
    packet_count = 25
    if packet_input.isdigit() and int(packet_input) > 0:
        packet_count = int(packet_input)
    return {"mode": "count", "count": packet_count}


def choose_bpf_filter() -> str:
    print()
    print(Colors.CYAN + "Choose Traffic Filter:" + Colors.RESET)
    print(Colors.WHITE + "1. No Filter" + Colors.RESET)
    print(Colors.WHITE + "2. TCP Only" + Colors.RESET)
    print(Colors.WHITE + "3. UDP Only" + Colors.RESET)
    print(Colors.WHITE + "4. ICMP Only" + Colors.RESET)
    print(Colors.WHITE + "5. DNS Traffic" + Colors.RESET)
    print(Colors.WHITE + "6. HTTP/HTTPS Traffic" + Colors.RESET)
    print(Colors.WHITE + "7. Custom BPF Filter\n" + Colors.RESET)

    choice = ask_input("Enter Choice [ 1 / 2 / 3 / 4 / 5 / 6 / 7 ] : ").strip()

    if choice == "2":
        return "tcp"
    if choice == "3":
        return "udp"
    if choice == "4":
        return "icmp"
    if choice == "5":
        return "port 53"
    if choice == "6":
        return "port 80 or port 443 or port 8080 or port 8443"
    if choice == "7":
        custom = ask_input("Enter Custom BPF Filter : ").strip()
        return custom
    return ""


def start_sniff(capture_config: dict, bpf_filter: str):
    captured_rows = []
    protocol_counter = Counter()
    direction_counter = Counter()
    tcp_flag_counter = Counter()
    talker_counter = Counter()
    endpoint_counter = Counter()
    dns_counter = Counter()
    http_host_counter = Counter()
    suspicious_port_counter = Counter()
    length_buckets = Counter()
    risk_counter = Counter()
    packet_timestamps = []

    local_ips = get_local_ipv4_addresses()

    def packet_callback(packet):
        info = extract_packet_info(packet, local_ips)
        captured_rows.append(info)

        protocol_counter[info["protocol"]] += 1
        direction_counter[info["direction"]] += 1
        risk_counter[info["risk"]] += 1
        packet_timestamps.append(time.time())

        if info["protocol"] == "TCP" and info["tcp_flags"] != "-":
            tcp_flag_counter[info["tcp_flags"]] += 1

        if info["src_ip"] != "N/A":
            talker_counter[info["src_ip"]] += 1
            endpoint_counter[f"{info['src_ip']} -> {info['dst_ip']}"] += 1

        if info["dns_query"] != "-":
            dns_counter[info["dns_query"]] += 1

        if info["http_host"] != "-":
            http_host_counter[info["http_host"]] += 1

        for port_value in [info["src_port"], info["dst_port"]]:
            if str(port_value).isdigit() and int(port_value) in COMMON_SUSPICIOUS_PORTS:
                suspicious_port_counter[int(port_value)] += 1

        length = info["length"]
        if length < 100:
            length_buckets["Small (<100B)"] += 1
        elif length < 1000:
            length_buckets["Medium (100-999B)"] += 1
        else:
            length_buckets["Large (>=1000B)"] += 1

    sniff_kwargs = {
        "prn": packet_callback,
        "store": False
    }

    if bpf_filter:
        sniff_kwargs["filter"] = bpf_filter

    if capture_config["mode"] == "count":
        sniff_kwargs["count"] = capture_config["count"]
    else:
        sniff_kwargs["timeout"] = capture_config["seconds"]

    sniff(**sniff_kwargs)

    analysis = {
        "protocol_counter": protocol_counter,
        "direction_counter": direction_counter,
        "tcp_flag_counter": tcp_flag_counter,
        "talker_counter": talker_counter,
        "endpoint_counter": endpoint_counter,
        "dns_counter": dns_counter,
        "http_host_counter": http_host_counter,
        "suspicious_port_counter": suspicious_port_counter,
        "length_buckets": length_buckets,
        "risk_counter": risk_counter,
        "packet_timestamps": packet_timestamps
    }

    return captured_rows, analysis


def calculate_burst_score(packet_timestamps: list) -> tuple[int, str]:
    if not packet_timestamps:
        return 0, "No Traffic"

    second_buckets = Counter(int(ts) for ts in packet_timestamps)
    peak_per_second = max(second_buckets.values()) if second_buckets else 0

    if peak_per_second >= 25:
        return peak_per_second, "High Burst"
    if peak_per_second >= 10:
        return peak_per_second, "Moderate Burst"
    return peak_per_second, "Low Burst"


# =========================
# RENDERING
# =========================
def render_packet_table(packet_rows: list, limit: int = 20):
    print("\n" + Colors.CYAN + Colors.BOLD + "Captured Packet Details:" + Colors.RESET)

    border = "+--------------------------------------------------------------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(
        Colors.WHITE +
        f"|{'#':^4}|{'Time':^10}|{'Source IP':^16}|{'Destination IP':^16}|{'Proto':^7}|{'SPort':^8}|{'DPort':^8}|{'Dir':^12}|{'Risk':^12}|{'Flags/DNS/HTTP Hint':^50}|" +
        Colors.RESET
    )
    print(Colors.CYAN + border + Colors.RESET)

    if not packet_rows:
        print(
            Colors.WHITE +
            f"|{'-':^4}|{'-':^10}|{'None':^16}|{'None':^16}|{'-':^7}|{'-':^8}|{'-':^8}|{'-':^12}|{'-':^12}|{'No packets captured':^50}|" +
            Colors.RESET
        )
    else:
        for idx, row in enumerate(packet_rows[:limit], start=1):
            proto_color = Colors.WHITE
            if row["protocol"] == "TCP":
                proto_color = Colors.GREEN
            elif row["protocol"] == "UDP":
                proto_color = Colors.YELLOW
            elif row["protocol"] == "ICMP":
                proto_color = Colors.MAGENTA
            else:
                proto_color = Colors.RED

            risk_color = Colors.GREEN
            if row["risk"] == "Medium":
                risk_color = Colors.YELLOW
            elif row["risk"] == "High":
                risk_color = Colors.RED

            hint = row["tcp_flags"]
            if row["dns_query"] != "-":
                hint = f"DNS:{row['dns_query'][:50]}"
            elif row["http_host"] != "-":
                hint = f"HTTP Host:{row['http_host'][:46]}"

            print(
                Colors.WHITE + "|" +
                f"{idx:^4}" +
                "|" +
                f"{row['timestamp']:^10}" +
                "|" +
                f"{row['src_ip'][:16]:^16}" +
                "|" +
                f"{row['dst_ip'][:16]:^16}" +
                "|" +
                proto_color + f"{row['protocol']:^7}" +
                Colors.WHITE + "|" +
                f"{row['src_port']:^8}" +
                "|" +
                f"{row['dst_port']:^8}" +
                "|" +
                Colors.CYAN + f"{row['direction'][:10]:^12}" +
                Colors.WHITE + "|" +
                risk_color + f"{row['risk']:^12}" +
                Colors.WHITE + "|" +
                Colors.YELLOW + f"{hint[:58]:<50}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_summary(analysis: dict, total_packets: int):
    burst_value, burst_label = calculate_burst_score(analysis["packet_timestamps"])

    print("\n" + Colors.CYAN + Colors.BOLD + "Packet Capture Summary:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^38}|{'Status':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    burst_color = Colors.GREEN
    if burst_label == "Moderate Burst":
        burst_color = Colors.YELLOW
    elif burst_label == "High Burst":
        burst_color = Colors.RED

    rows = [
        ("Total Packets", str(total_packets), Colors.WHITE),
        ("TCP Packets", str(analysis["protocol_counter"].get("TCP", 0)), Colors.GREEN),
        ("UDP Packets", str(analysis["protocol_counter"].get("UDP", 0)), Colors.YELLOW),
        ("ICMP Packets", str(analysis["protocol_counter"].get("ICMP", 0)), Colors.MAGENTA),
        ("Other Packets", str(analysis["protocol_counter"].get("OTHER", 0)), Colors.RED),
        ("Peak PPS Bucket", str(burst_value), burst_color),
        ("Traffic Burst", burst_label, burst_color),
    ]

    for label, value, color in rows:
        print(
            Colors.WHITE + "|" +
            f"{label:<38}" +
            "|" +
            color + f"{value:^15}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_distribution_table(title: str, counter: Counter):
    print("\n" + Colors.MAGENTA + Colors.BOLD + title + ":" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Value':^38}|{'Count':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    items = counter.most_common()
    if not items:
        print(Colors.WHITE + f"|{'None':^38}|{'0':^15}|" + Colors.RESET)
    else:
        for value, count in items:
            print(
                Colors.WHITE + "|" +
                Colors.YELLOW + f"{str(value)[:38]:<38}" +
                Colors.WHITE + "|" +
                Colors.YELLOW + f"{str(count):^15}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )
    print(Colors.CYAN + border + Colors.RESET)


def render_talker_table(title: str, items: list, limit: int = 10):
    print("\n" + Colors.CYAN + Colors.BOLD + title + ":" + Colors.RESET)

    border = "+--------------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^5}|{'IP':^18}|{'Country':^18}|{'City':^18}|{'ISP':^32}|{'Hits':^8}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    if not items:
        print(Colors.WHITE + f"|{'-':^5}|{'None':^18}|{'None':^18}|{'None':^18}|{'None':^32}|{'0':^8}|" + Colors.RESET)
    else:
        for idx, (ip, count) in enumerate(items[:limit], start=1):
            geo = get_geoip(ip)
            print(
                Colors.WHITE + "|" +
                f"{idx:^5}" +
                "|" +
                Colors.YELLOW + f"{ip[:18]:^18}" +
                Colors.WHITE + "|" +
                f"{geo['country'][:18]:^18}" +
                "|" +
                f"{geo['city'][:18]:^18}" +
                "|" +
                f"{geo['isp'][:32]:^32}" +
                "|" +
                Colors.MAGENTA + f"{str(count):^8}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_endpoint_table(title: str, items: list, limit: int = 10):
    print("\n" + Colors.CYAN + Colors.BOLD + title + ":" + Colors.RESET)

    border = "+------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Conversation':^80}|{'Count':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    if not items:
        print(Colors.WHITE + f"|{'None':^80}|{'0':^15}|" + Colors.RESET)
    else:
        for value, count in items[:limit]:
            print(
                Colors.WHITE + "|" +
                Colors.YELLOW + f"{str(value)[:80]:<80}" +
                Colors.WHITE + "|" +
                Colors.YELLOW + f"{str(count):^15}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_recommendations(analysis: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Recommendations:" + Colors.RESET)

    border = "+------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^6}|{'Recommendation':^65}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    recommendations = []

    if analysis["risk_counter"].get("High", 0) > 0:
        recommendations.append("Review traffic involving high-risk ports first.")
    if analysis["direction_counter"].get("Inbound", 0) > analysis["direction_counter"].get("Outbound", 0):
        recommendations.append("Inbound-heavy traffic may deserve closer inspection.")
    if analysis["dns_counter"]:
        recommendations.append("Inspect repeated DNS lookups for beaconing patterns.")
    if analysis["http_host_counter"]:
        recommendations.append("Review HTTP hostnames for suspicious destinations.")
    if analysis["suspicious_port_counter"]:
        recommendations.append("Validate services exposed on sensitive or admin ports.")
    if analysis["endpoint_counter"]:
        recommendations.append("Check top conversations for repeated source-destination pairs.")
    if analysis["tcp_flag_counter"]:
        recommendations.append("Inspect unusual TCP flag mixes for scanning or resets.")
    if not recommendations:
        recommendations.append("No unusual traffic indicators observed in this capture.")

    deduped = []
    for item in recommendations:
        if item not in deduped:
            deduped.append(item)

    for idx, item in enumerate(deduped[:8], start=1):
        print(
            Colors.WHITE + "|" +
            f"{str(idx):^6}" +
            "|" +
            Colors.YELLOW + f"{item[:65]:<65}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


# =========================
# MAIN
# =========================
def main():
    print_banner()

    print_message(Colors.BLUE + "[i] Mode        : Live Packet Capture")
    print_message(Colors.BLUE + "[i] Input Type  : Network Traffic")
    print_message(Colors.BLUE + "[i] Detection   : Protocol / Direction / DNS / HTTP / Port Risk")
    print_message(Colors.BLUE + "[i] Features    : Top Talkers + GeoIP + Burst Insight + TCP Flags\n")

    if not SCAPY_AVAILABLE:
        print_message(Colors.RED + "[!] Scapy is not installed.")
        print_message(Colors.YELLOW + "Install it with: py -m pip install scapy")
        sys.exit(1)

    try:
        capture_config = choose_capture_mode()
        bpf_filter = choose_bpf_filter()

        print()
        print_message(Colors.YELLOW + "[-] Starting Live Packet Capture ...")
        if bpf_filter:
            print_message(Colors.YELLOW + f"[-] Applied Filter : {bpf_filter}")
        print_message(Colors.YELLOW + "[-] Waiting for Packets ...\n")

        captured_rows, analysis = start_sniff(capture_config, bpf_filter)

        render_packet_table(captured_rows, limit=20)
        render_summary(analysis, len(captured_rows))
        render_distribution_table("Direction Distribution", analysis["direction_counter"])
        render_distribution_table("Packet Size Distribution", analysis["length_buckets"])
        render_distribution_table("Risk Distribution", analysis["risk_counter"])
        render_distribution_table("TCP Flag Distribution", analysis["tcp_flag_counter"])
        render_distribution_table("Suspicious Port Hits", analysis["suspicious_port_counter"])
        render_distribution_table("Top DNS Queries", analysis["dns_counter"])
        render_distribution_table("Top HTTP Hosts", analysis["http_host_counter"])
        render_talker_table("Top Talkers", analysis["talker_counter"].most_common(10))
        render_endpoint_table("Top Conversations", analysis["endpoint_counter"].most_common(10))
        render_recommendations(analysis)

    except KeyboardInterrupt:
        print_message("\n" + Colors.RED + "[!] Capture Interrupted by User.")
        sys.exit(0)
    except PermissionError:
        print_message(Colors.RED + "[!] Permission Denied - Run Terminal as Administrator/Root.")
        sys.exit(1)
    except socket.error as exc:
        print_message(Colors.RED + f"[!] Socket Error: {exc}")
        sys.exit(1)
    except Exception as exc:
        print_message(Colors.RED + f"[!] Unexpected Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    time.sleep(60)