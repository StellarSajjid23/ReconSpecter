#!/usr/bin/env python3

import socket
import time
import sys
import ipaddress
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# OPTIONAL IMPORTS
# =========================
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from scapy.all import IP, TCP, ICMP, sr1, send, conf
    SCAPY_AVAILABLE = True
    conf.verb = 0
except ImportError:
    SCAPY_AVAILABLE = False

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
                        +------------------------------------------------------------------+
                        |    ____            _     ____                                    |
                        |   |  _ \ ___  _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ ___  |
                        |   | |_) / _ \| '__| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|  |
                        |   |  __/ (_) | |  | |_   ___) | (_| (_| | | | | | | |  __/ |     |
                        |   |_|   \___/|_|   \__| |____/ \___\__,_|_| |_|_| |_|\___|_|     |
                        |                                                                  |
                        +------------------------------------------------------------------+
                        |                   Exposure Profiling Edition                     |
                        +------------------------------------------------------------------+
"""
    print(Colors.RED + banner + Colors.RESET)
    print(Colors.CYAN + "[*] Internship Portfolio Edition" + Colors.RESET)
    print(Colors.GREEN + "[*] Author: StellarSajjid23" + Colors.RESET)
    print(Colors.YELLOW + "[*] Engine: Advanced Port Scanner + Exposure Profiler" + Colors.RESET)


# =========================
# CONSTANTS
# =========================
TOP_COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 902, 989, 990, 993,
    995, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2375, 2376,
    3306, 3389, 3690, 4369, 4444, 4500, 5000, 5060, 5432, 5601, 5672, 5900, 5985, 5986, 6379,
    6443, 6667, 7001, 7077, 7199, 7474, 8000, 8008, 8080, 8081, 8086, 8088, 8161, 8443, 8500,
    8888, 9000, 9042, 9090, 9200, 9300, 9418, 9999, 10000, 11211, 15672, 27017, 50070
]

BANNER_PORTS = {
    21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 993, 995,
    1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200
}

HIGH_RISK_PORTS = {
    20, 21, 23, 69, 111, 135, 137, 138, 139, 445, 512, 513, 514,
    1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 27017
}

COMMON_PORT_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    902: "vmware",
    989: "ftps-data",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    1883: "mqtt",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2181: "zookeeper",
    2375: "docker",
    2376: "docker-tls",
    3306: "mysql",
    3389: "rdp",
    4369: "epmd",
    4444: "metasploit-like",
    5000: "custom-web",
    5060: "sip",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-ssl",
    6379: "redis",
    6443: "kubernetes-api",
    7001: "weblogic",
    7077: "spark",
    7199: "cassandra-jmx",
    7474: "neo4j",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8086: "influxdb",
    8088: "spark-history",
    8161: "activemq",
    8443: "https-alt",
    8500: "consul",
    8888: "jupyter-like",
    9000: "sonarqube-like",
    9042: "cassandra",
    9090: "prometheus-like",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    9418: "git",
    9999: "custom-admin",
    10000: "webmin",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
    50070: "hadoop-namenode"
}


# =========================
# HELPERS
# =========================
def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print_message(Colors.RED + f"[!] Failed to resolve target: {target}")
        sys.exit(1)


def reverse_dns_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Not Found"


def get_ip_category(ip: str) -> str:
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


def get_ip_geolocation(ip: str) -> dict:
    result = {
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "timezone": "Unknown",
        "isp": "Unknown",
        "lat": "Unknown",
        "lon": "Unknown",
        "status_note": "GeoIP Unavailable"
    }

    category = get_ip_category(ip)
    if category != "Public":
        result["status_note"] = "Private/Internal/Non-Public"
        return result

    if not REQUESTS_AVAILABLE:
        result["status_note"] = "requests module not installed"
        return result

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data.get("status") == "success":
            result["country"] = data.get("country", "Unknown")
            result["region"] = data.get("regionName", "Unknown")
            result["city"] = data.get("city", "Unknown")
            result["timezone"] = data.get("timezone", "Unknown")
            result["isp"] = data.get("isp", "Unknown")
            result["lat"] = str(data.get("lat", "Unknown"))
            result["lon"] = str(data.get("lon", "Unknown"))
            result["status_note"] = "Success"
        else:
            result["status_note"] = "Lookup Failed"
    except Exception:
        result["status_note"] = "Lookup Failed"

    return result


def parse_port_range(port_range: str):
    try:
        start_port, end_port = map(int, port_range.split("-"))
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError
        if start_port > end_port:
            raise ValueError
        return start_port, end_port
    except ValueError:
        print_message(Colors.RED + "[!] Invalid port range. Use format like 1-1000")
        sys.exit(1)


def parse_port_list(port_list_text: str):
    ports = set()
    parts = [part.strip() for part in port_list_text.split(",") if part.strip()]

    if not parts:
        print_message(Colors.RED + "[!] Empty port list provided.")
        sys.exit(1)

    try:
        for part in parts:
            if "-" in part:
                start_port, end_port = parse_port_range(part)
                for port in range(start_port, end_port + 1):
                    ports.add(port)
            else:
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValueError
                ports.add(port)
    except ValueError:
        print_message(Colors.RED + "[!] Invalid custom port list. Example: 22,80,443,8000-8080")
        sys.exit(1)

    return sorted(list(ports))


def get_service_name(port: int) -> str:
    if port in COMMON_PORT_SERVICES:
        return COMMON_PORT_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def is_http_like(port: int, service_name: str) -> bool:
    service_name = service_name.lower()
    return (
        port in {80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000}
        or "http" in service_name
        or "https" in service_name
    )


def classify_port_exposure(port: int, service: str) -> str:
    service = service.lower()

    if port in HIGH_RISK_PORTS:
        return "High Risk Exposure"

    if port in {22, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 993, 995, 6443, 8443}:
        return "Common Exposure"

    if service in {
        "ssh", "http", "https", "smtp", "imap", "pop3", "dns", "ldap",
        "submission", "imaps", "pop3s", "kubernetes-api", "https-alt"
    }:
        return "Common Exposure"

    if service == "unknown":
        return "Unknown Service"

    return "Limited Exposure"


def calculate_risk_score(open_ports: list) -> tuple[int, str]:
    score = 0

    for port in open_ports:
        if port in HIGH_RISK_PORTS:
            score += 10
        elif port in {22, 80, 443, 8080, 8443, 25, 53, 389}:
            score += 4
        else:
            score += 2

    score = min(score, 100)

    if score >= 60:
        return score, "High"
    if score >= 30:
        return score, "Medium"
    return score, "Low"


def guess_host_profile(open_ports: list) -> str:
    port_set = set(open_ports)

    if not port_set:
        return "No Exposed Services Detected"

    if {80, 443}.intersection(port_set) and {3306, 5432, 1433, 27017}.intersection(port_set):
        return "Web + Database Host"

    if {80, 443, 8080, 8443, 8000, 8888}.intersection(port_set):
        return "Web Application Host"

    if {22, 3389, 5985, 5986}.intersection(port_set) and len(port_set) <= 4:
        return "Management / Admin Access Host"

    if {3306, 5432, 1433, 1521, 27017, 6379}.intersection(port_set):
        return "Database-Oriented Host"

    if {25, 465, 587, 110, 143, 993, 995}.intersection(port_set):
        return "Mail-Oriented Host"

    if {445, 139}.intersection(port_set):
        return "Windows / SMB-Oriented Host"

    if {2049, 111}.intersection(port_set):
        return "Unix / NFS-Oriented Host"

    if {6443, 2375, 2376, 8500}.intersection(port_set):
        return "Container / Orchestration Host"

    return "General Purpose Exposed Host"


# =========================
# DISCOVERY
# =========================
def host_discovery(ip: str) -> tuple[bool, str]:
    # Fast TCP connect-based check first
    discovery_ports = [80, 443, 22, 3389]
    for port in discovery_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.7)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True, f"TCP Response on Port {port}"
        except Exception:
            continue

    # Optional ICMP with Scapy
    if SCAPY_AVAILABLE:
        try:
            packet = IP(dst=ip) / ICMP()
            response = sr1(packet, timeout=1, verbose=0)
            if response is not None:
                return True, "ICMP Reply Received"
        except Exception:
            pass

    return False, "No Discovery Response"


# =========================
# BANNER GRABBING
# =========================
def grab_banner(ip: str, port: int, service: str) -> str:
    service = service.lower()

    # HTTPS / TLS
    if port in {443, 8443, 993, 995, 465, 5986} or "https" in service or service in {"imaps", "pop3s", "smtps"}:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=2.5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                    cert = tls_sock.getpeercert()
                    subject = cert.get("subject", [])
                    subject_text = []
                    for item in subject:
                        for key, value in item:
                            subject_text.append(f"{key}={value}")
                    if subject_text:
                        return "TLS Cert: " + ", ".join(subject_text)[:55]
                    return "TLS Service"
        except Exception:
            return "-"

    # HTTP-like
    if is_http_like(port, service):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.5)
            sock.connect((ip, port))
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: ExposureProfiler\r\n\r\n"
            sock.sendall(request.encode())
            data = sock.recv(256)
            sock.close()
            text = data.decode(errors="ignore").replace("\r", " ").replace("\n", " ").strip()
            return text[:55] if text else "-"
        except Exception:
            return "-"

    # Plain TCP banner
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        try:
            data = sock.recv(256)
            if data:
                text = data.decode(errors="ignore").replace("\r", " ").replace("\n", " ").strip()
                sock.close()
                return text[:55] if text else "-"
        except Exception:
            pass

        if service in {"smtp", "pop3", "imap", "ftp", "telnet"}:
            try:
                sock.sendall(b"\r\n")
                data = sock.recv(256)
                text = data.decode(errors="ignore").replace("\r", " ").replace("\n", " ").strip()
                sock.close()
                return text[:55] if text else "-"
            except Exception:
                pass

        sock.close()
    except Exception:
        pass

    return "-"


# =========================
# SCAN METHODS
# =========================
def syn_scan_port(ip: str, port: int):
    """
    Returns: (port, status, latency_ms)
    status = OPEN / CLOSED / FILTERED / ERROR
    """
    if not SCAPY_AVAILABLE:
        return port, "ERROR", 0.0

    start_time = time.time()

    try:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        latency_ms = round((time.time() - start_time) * 1000, 2)

        if response is None:
            return port, "FILTERED", latency_ms

        if response.haslayer(TCP):
            flags = response[TCP].flags
            if flags == 0x12:  # SYN-ACK
                send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=0)
                return port, "OPEN", latency_ms
            if flags == 0x14:  # RST-ACK
                return port, "CLOSED", latency_ms

        if response.haslayer(ICMP):
            return port, "FILTERED", latency_ms

        return port, "FILTERED", latency_ms

    except PermissionError:
        return port, "ERROR", 0.0
    except Exception:
        return port, "FILTERED", 0.0


def connect_scan_port(ip: str, port: int):
    """
    Returns: (port, status, latency_ms)
    """
    start_time = time.time()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((ip, port))
        latency_ms = round((time.time() - start_time) * 1000, 2)
        sock.close()

        if result == 0:
            return port, "OPEN", latency_ms

        if result in {111, 61, 10061}:
            return port, "CLOSED", latency_ms

        return port, "FILTERED", latency_ms
    except Exception:
        return port, "ERROR", 0.0


def run_threaded_scan(ip: str, ports: list, scan_mode: str = "connect", workers: int = 150):
    open_ports = []
    closed_count = 0
    filtered_count = 0
    error_count = 0
    latency_map = {}

    scanner = connect_scan_port
    if scan_mode == "syn":
        scanner = syn_scan_port

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scanner, ip, port): port for port in ports}

        for future in as_completed(futures):
            try:
                port, status, latency_ms = future.result()
                latency_map[port] = latency_ms

                if status == "OPEN":
                    open_ports.append(port)
                elif status == "CLOSED":
                    closed_count += 1
                elif status == "FILTERED":
                    filtered_count += 1
                else:
                    error_count += 1

            except Exception:
                error_count += 1

    open_ports.sort()
    return open_ports, closed_count, filtered_count, error_count, latency_map


# =========================
# ENRICHMENT
# =========================
def enrich_open_ports(ip: str, open_ports: list, latency_map: dict):
    results = []

    for port in open_ports:
        service = get_service_name(port)
        exposure = classify_port_exposure(port, service)
        banner = "-"

        if port in BANNER_PORTS or is_http_like(port, service):
            banner = grab_banner(ip, port, service)

        latency_ms = latency_map.get(port, 0.0)

        if exposure == "High Risk Exposure":
            risk_tag = "High"
        elif exposure == "Common Exposure":
            risk_tag = "Medium"
        elif exposure == "Unknown Service":
            risk_tag = "Medium"
        else:
            risk_tag = "Low"

        results.append({
            "port": port,
            "service": service,
            "exposure": exposure,
            "risk_tag": risk_tag,
            "latency_ms": latency_ms,
            "banner": banner
        })

    return results


# =========================
# RENDERING
# =========================
def render_target_profile(target: str, ip: str, reverse_dns: str, category: str, geo: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Target Profile:" + Colors.RESET)
    border = "+------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^28}|{'Status':^61}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("Target", target),
        ("Resolved IP", ip),
        ("Reverse DNS", reverse_dns),
        ("IP Category", category),
        ("Country", geo.get("country", "Unknown")),
        ("Region", geo.get("region", "Unknown")),
        ("City", geo.get("city", "Unknown")),
        ("ISP", geo.get("isp", "Unknown")),
        ("Timezone", geo.get("timezone", "Unknown")),
        ("GeoIP Note", geo.get("status_note", "Unknown")),
    ]

    for label, value in rows:
        print(
            Colors.WHITE + "|" +
            f"{label:<28}" +
            "|" +
            Colors.YELLOW + f"{str(value)[:61]:^61}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_open_ports_table(port_results: list):
    print("\n" + Colors.CYAN + Colors.BOLD + "Open Port Results:" + Colors.RESET)

    border = "+-------------------------------------------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(
        Colors.WHITE +
        f"|{'Port':^8}|{'Service':^18}|{'Exposure':^22}|{'Risk':^10}|{'Latency':^10}|{'Banner / Fingerprint':^60}|" +
        Colors.RESET
    )
    print(Colors.CYAN + border + Colors.RESET)

    if not port_results:
        print(
            Colors.WHITE +
            f"|{'-':^8}|{'None':^18}|{'-':^22}|{'-':^10}|{'-':^10}|{'No open ports found':^60}|" +
            Colors.RESET
        )
    else:
        for item in port_results:
            exposure_color = Colors.GREEN
            if item["exposure"] == "Common Exposure":
                exposure_color = Colors.YELLOW
            elif item["exposure"] in {"High Risk Exposure", "Unknown Service"}:
                exposure_color = Colors.RED

            risk_color = Colors.GREEN
            if item["risk_tag"] == "Medium":
                risk_color = Colors.YELLOW
            elif item["risk_tag"] == "High":
                risk_color = Colors.RED

            latency_text = f"{item['latency_ms']}ms" if item["latency_ms"] else "-"

            print(
                Colors.WHITE + "|" +
                f"{str(item['port']):^8}" +
                "|" +
                Colors.YELLOW + f"{item['service'][:18]:^18}" +
                Colors.WHITE + "|" +
                exposure_color + f"{item['exposure'][:22]:^22}" +
                Colors.WHITE + "|" +
                risk_color + f"{item['risk_tag']:^10}" +
                Colors.WHITE + "|" +
                Colors.CYAN + f"{latency_text:^10}" +
                Colors.WHITE + "|" +
                Colors.GREEN + f"{item['banner'][:60]:^60}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_scan_summary(open_count: int, closed_count: int, filtered_count: int, error_count: int, risk_score: int, risk_level: str, profile_guess: str):
    print("\n" + Colors.CYAN + Colors.BOLD + "Scan Summary:" + Colors.RESET)

    border = "+------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^28}|{'Status':^43}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    risk_color = Colors.GREEN
    if risk_level == "Medium":
        risk_color = Colors.YELLOW
    elif risk_level == "High":
        risk_color = Colors.RED

    rows = [
        ("Open Ports", str(open_count), Colors.GREEN),
        ("Closed Ports", str(closed_count), Colors.RED),
        ("Filtered Ports", str(filtered_count), Colors.YELLOW),
        ("Errors", str(error_count), Colors.MAGENTA),
        ("Risk Score", str(risk_score), risk_color),
        ("Risk Level", risk_level, risk_color),
        ("Likely Host Role", profile_guess, Colors.CYAN),
    ]

    for label, value, color in rows:
        print(
            Colors.WHITE + "|" +
            f"{label:<28}" +
            "|" +
            color + f"{str(value)[:43]:^43}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_top_exposures(port_results: list, limit: int = 8):
    print("\n" + Colors.MAGENTA + Colors.BOLD + "Top Exposure Notes:" + Colors.RESET)

    border = "+-------------------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^5}|{'Port':^8}|{'Service':^18}|{'Note':^75}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    sorted_items = sorted(
        port_results,
        key=lambda x: ({"High": 3, "Medium": 2, "Low": 1}.get(x["risk_tag"], 0), x["port"]),
        reverse=True
    )

    if not sorted_items:
        print(Colors.WHITE + f"|{'-':^5}|{'-':^8}|{'None':^18}|{'No exposure notes available':^75}|" + Colors.RESET)
    else:
        for idx, item in enumerate(sorted_items[:limit], start=1):
            note = build_exposure_note(item["port"], item["service"], item["risk_tag"], item["banner"])
            print(
                Colors.WHITE + "|" +
                f"{idx:^5}" +
                "|" +
                f"{str(item['port']):^8}" +
                "|" +
                Colors.YELLOW + f"{item['service'][:18]:^18}" +
                Colors.WHITE + "|" +
                Colors.GREEN + f"{note[:75]:<75}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_recommendations(port_results: list, ip_category: str):
    print("\n" + Colors.CYAN + Colors.BOLD + "Recommendations:" + Colors.RESET)

    border = "+---------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^6}|{'Recommendation':^56}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    recommendations = []

    if not port_results:
        recommendations.append("No exposed TCP services were detected.")
        recommendations.append("Re-check with a wider range if required.")
    else:
        ports = {item["port"] for item in port_results}

        if HIGH_RISK_PORTS.intersection(ports):
            recommendations.append("Review high-risk services exposed to the network.")
        if 23 in ports:
            recommendations.append("Replace Telnet with SSH where possible.")
        if 21 in ports:
            recommendations.append("Review FTP exposure; prefer secure alternatives.")
        if 445 in ports or 139 in ports:
            recommendations.append("Restrict SMB exposure to trusted networks only.")
        if 3389 in ports:
            recommendations.append("Ensure RDP is gated behind VPN/MFA controls.")
        if 2375 in ports:
            recommendations.append("Docker remote API is risky if exposed publicly.")
        if 6379 in ports:
            recommendations.append("Check Redis authentication and bind settings.")
        if 9200 in ports:
            recommendations.append("Verify Elasticsearch is not anonymously exposed.")
        if any(is_http_like(item["port"], item["service"]) for item in port_results):
            recommendations.append("Review web ports for TLS and auth hardening.")

        if ip_category == "Public":
            recommendations.append("Public-facing hosts should be reviewed urgently.")

    deduped = []
    for item in recommendations:
        if item not in deduped:
            deduped.append(item)

    for idx, item in enumerate(deduped[:6], start=1):
        print(
            Colors.WHITE + "|" +
            f"{str(idx):^6}" +
            "|" +
            Colors.YELLOW + f"{item[:56]:<56}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def build_exposure_note(port: int, service: str, risk_tag: str, banner: str) -> str:
    if port == 22:
        return "SSH exposed; validate strong auth, key use, and source restrictions."
    if port == 23:
        return "Telnet exposed; unencrypted remote access is high risk."
    if port == 21:
        return "FTP exposed; verify credentials and secure transfer alternatives."
    if port == 445:
        return "SMB exposed; common target for lateral movement and worms."
    if port == 3389:
        return "RDP exposed; require MFA, VPN, and rate limits."
    if port == 2375:
        return "Docker API exposed; can allow remote container control."
    if port == 6379:
        return "Redis exposed; check authentication and protected mode."
    if port == 9200:
        return "Elasticsearch exposed; verify access control and indexing privacy."
    if port == 3306:
        return "MySQL exposed; restrict remote access and validate auth."
    if port == 5432:
        return "PostgreSQL exposed; confirm trusted hosts and encryption."
    if banner != "-" and banner:
        return f"Banner observed: {banner[:40]}"
    return f"{service} is reachable; review necessity and access scope. ({risk_tag})"


# =========================
# USER WORKFLOW
# =========================
def choose_scan_mode() -> str:
    print(Colors.CYAN + "Choose Scan Mode:" + Colors.RESET)
    print(Colors.WHITE + "1. TCP Connect Scan  [ Default / Safer ]" + Colors.RESET)
    print(Colors.WHITE + "2. TCP SYN Scan [ Scapy / Faster / Requires Privileges ]\n" + Colors.RESET)

    choice = ask_input("Enter Choice [ 1 / 2 ] : ").strip()

    if choice == "2":
        if not SCAPY_AVAILABLE:
            print_message(Colors.RED + "[!] Scapy is not installed. Falling back to TCP Connect Scan.")
            return "connect"
        return "syn"

    return "connect"


def choose_port_mode() -> list:
    print()
    print(Colors.CYAN + "Choose Port Selection Mode:" + Colors.RESET)
    print(Colors.WHITE + "1. Custom Range        [ Example: 1-1000 ]" + Colors.RESET)
    print(Colors.WHITE + "2. Top Common Ports    [ Fast Recon ]" + Colors.RESET)
    print(Colors.WHITE + "3. Custom Port List    [ Example: 22,80,443,8000-8080 ]\n" + Colors.RESET)

    choice = ask_input("Enter Choice [ 1 / 2 / 3 ] : ").strip()

    if choice == "2":
        return TOP_COMMON_PORTS

    if choice == "3":
        port_list_text = ask_input("Enter Custom Port List : ").strip()
        return parse_port_list(port_list_text)

    port_range = ask_input("Enter Port Range [ Example -> 1-1000 ] : ").strip()
    start_port, end_port = parse_port_range(port_range)
    return list(range(start_port, end_port + 1))


# =========================
# MAIN
# =========================
def main():
    print_banner()

    print("                                                                           ")
    target = ask_input("Enter Target [ IP or Website ] : ").strip()
    print()

    if not target:
        print_message(Colors.RED + "[!] No target provided.")
        sys.exit(1)

    scan_mode = choose_scan_mode()
    ports = choose_port_mode()

    workers_input = ask_input("Enter Worker Count [ Default 150 ] : ").strip()
    workers = 150
    if workers_input.isdigit() and int(workers_input) > 0:
        workers = min(int(workers_input), 500)

    target_ip = resolve_target(target)
    reverse_dns = reverse_dns_lookup(target_ip)
    ip_category = get_ip_category(target_ip)
    geo = get_ip_geolocation(target_ip)

    print()
    print_message(Colors.BLUE + f"[i] Target         : {target}")
    print_message(Colors.BLUE + f"[i] Resolved IP    : {target_ip}")
    print_message(Colors.BLUE + f"[i] Reverse DNS    : {reverse_dns}")
    print_message(Colors.BLUE + f"[i] IP Category    : {ip_category}")
    print_message(Colors.BLUE + f"[i] Scan Mode      : {'TCP SYN (Scapy)' if scan_mode == 'syn' else 'TCP Connect'}")
    print_message(Colors.BLUE + f"[i] Port Count     : {len(ports)}")
    print_message(Colors.BLUE + f"[i] Worker Threads : {workers}")

    print()
    print_message(Colors.YELLOW + f"[-] Scan Started at {time.strftime('[ %B %d : %Y : %I:%M %p : %A ]')}")
    print_message(Colors.YELLOW + "[-] Running Host Discovery ...")

    host_up, discovery_reason = host_discovery(target_ip)

    if host_up:
        print_message(Colors.GREEN + f"[+] Host Discovery : Responsive [ {discovery_reason} ]")
    else:
        print_message(Colors.YELLOW + f"[!] Host Discovery : No Clear Response ({discovery_reason})")
        print_message(Colors.YELLOW + "[!] Continuing Anyway; Host May Be Filtering Probes")

    print_message(Colors.YELLOW + "[-] Scanning Ports ...\n")

    try:
        open_ports, closed_count, filtered_count, error_count, latency_map = run_threaded_scan(
            target_ip,
            ports,
            scan_mode=scan_mode,
            workers=workers
        )

        enriched = enrich_open_ports(target_ip, open_ports, latency_map)
        risk_score, risk_level = calculate_risk_score(open_ports)
        profile_guess = guess_host_profile(open_ports)

        render_target_profile(target, target_ip, reverse_dns, ip_category, geo)
        render_open_ports_table(enriched)
        render_scan_summary(
            len(open_ports),
            closed_count,
            filtered_count,
            error_count,
            risk_score,
            risk_level,
            profile_guess
        )
        render_top_exposures(enriched)
        render_recommendations(enriched, ip_category)

        print_message(Colors.YELLOW + f"\n[-] Scan Completed at {time.strftime('[ %B %d : %Y : %I:%M %p : %A ]')}")
        print()
    except KeyboardInterrupt:
        print_message("\n" + Colors.RED + "[!] Scan Interrupted By User")
        sys.exit(0)
    except Exception as exc:
        print_message(Colors.RED + f"[!] Unexpected Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    time.sleep(60)

