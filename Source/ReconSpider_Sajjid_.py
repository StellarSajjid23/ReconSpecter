#!/usr/bin/env python3

import sys
import time
import re
import ssl
import socket
import ipaddress
from urllib.parse import urljoin, urlparse

import requests

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

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
# CONSTANTS
# =========================
COMMON_SENSITIVE_PATHS = [
    "/admin",
    "/login",
    "/administrator",
    "/wp-admin",
    "/backup",
    "/config",
    "/dashboard",
    "/phpmyadmin",
    "/server-status",
    "/.git/",
    "/.git/config",
    "/.env",
    "/backup.zip",
    "/config.php.bak",
    "/db.sql",
    "/test/",
    "/dev/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/api/",
    "/status",
    "/console",
    "/manage",
]

LOGIN_HINT_PATHS = [
    "/login",
    "/signin",
    "/auth",
    "/user/login",
    "/account/login",
    "/admin/login",
]

ADMIN_HINT_PATHS = [
    "/admin",
    "/administrator",
    "/dashboard",
    "/manage",
    "/console",
    "/cpanel",
]

BACKUP_HINT_PATHS = [
    "/backup.zip",
    "/db.sql",
    "/.env",
    "/config.php.bak",
    "/old/",
    "/dev/",
    "/test/",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "Clickjacking Protection",
    "X-Content-Type-Options": "MIME Sniffing Protection",
    "Referrer-Policy": "Referrer Policy",
    "Permissions-Policy": "Permissions Policy",
    "Cross-Origin-Opener-Policy": "COOP",
    "Cross-Origin-Resource-Policy": "CORP",
}

WAF_HINT_HEADERS = {
    "cloudflare": "Cloudflare",
    "cf-ray": "Cloudflare",
    "akamai": "Akamai",
    "x-akamai": "Akamai",
    "incapsula": "Imperva Incapsula",
    "sucuri": "Sucuri",
    "x-sucuri": "Sucuri",
    "f5": "F5",
    "x-cdn": "CDN/WAF",
    "fastly": "Fastly",
    "x-served-by": "Fastly/CDN",
}

INTERESTING_JS_TERMS = [
    "admin", "api", "debug", "token", "auth", "config",
    "secret", "key", "session", "internal", "private"
]

REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 ReconSpider Educational Security Review"
}


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
      +-----------------------------------------------------------------------------+
      |      ______                             ______       _     _                |
      |     (_____ \                           / _____)     (_)   | |               |
      |      _____) )_____  ____ ___  ____    ( (____  ____  _  __| |_____  ____    |
      |     |  __  /| ___ |/ ___) _ \|  _ \    \____ \|  _ \| |/ _  | ___ |/ ___)   |
      |     | |  \ \| ____( (__| |_| | | | |   _____) ) |_| | ( (_| | ____| |       |
      |     |_|   |_|_____)\____)___/|_| |_|  (______/|  __/|_|\____|_____)_|       |
      |                                               |_|                           | 
      +-----------------------------------------------------------------------------+
      |                         Web Attack Surface Mapper                           |
      +-----------------------------------------------------------------------------+

"""
    print(Colors.RED + banner + Colors.RESET)
    print(Colors.CYAN + "[*] Internship Portfolio Edition" + Colors.RESET)
    print(Colors.GREEN + "[*] Author: StellarSajjid23" + Colors.RESET)
    print(Colors.YELLOW + "[*] Engine: Safe Web Exposure and Hardening Review" + Colors.RESET)
    print("                                                     ")


# =========================
# NETWORK / GEO HELPERS
# =========================
def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return "Resolution Failed"


def reverse_dns_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Not Found"


def get_ip_geolocation(ip: str) -> dict:
    result = {
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "timezone": "Unknown",
        "isp": "Unknown",
        "note": "Unavailable"
    }

    if not is_public_ip(ip):
        result["note"] = "Private/Internal/Non-Public"
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
            result["note"] = "Success"
        else:
            result["note"] = "Lookup Failed"
    except Exception:
        result["note"] = "Lookup Failed"

    return result


# =========================
# REQUEST HELPERS
# =========================
def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target


def fetch_url(url: str, allow_redirects: bool = True, method: str = "GET"):
    try:
        if method == "HEAD":
            response = requests.head(
                url,
                timeout=10,
                allow_redirects=allow_redirects,
                verify=True,
                headers=REQUEST_HEADERS
            )
        else:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=allow_redirects,
                verify=True,
                headers=REQUEST_HEADERS
            )
        return response
    except requests.RequestException:
        return None


def build_redirect_chain(response) -> list:
    chain = []
    if not response:
        return chain

    try:
        for item in response.history:
            chain.append(f"{item.status_code} -> {item.url}")
        chain.append(f"{response.status_code} -> {response.url}")
    except Exception:
        pass

    return chain


# =========================
# HEADER / COOKIE CHECKS
# =========================
def check_security_headers(response) -> dict:
    findings = {}
    headers = response.headers

    for header_name, friendly_name in SECURITY_HEADERS.items():
        findings[friendly_name] = header_name in headers

    return findings


def check_cookie_flags(response) -> dict:
    set_cookie_headers = response.headers.get("Set-Cookie", "")
    if not set_cookie_headers:
        return {
            "cookie_present": False,
            "secure_flag": False,
            "httponly_flag": False,
            "samesite_flag": False,
        }

    lowered = set_cookie_headers.lower()
    return {
        "cookie_present": True,
        "secure_flag": "secure" in lowered,
        "httponly_flag": "httponly" in lowered,
        "samesite_flag": "samesite" in lowered,
    }


def check_directory_listing(response) -> bool:
    body = response.text.lower()
    indicators = [
        "index of /",
        "directory listing for",
        "parent directory",
    ]
    return any(indicator in body for indicator in indicators)


# =========================
# FORM / CONTENT CHECKS
# =========================
def check_forms(response) -> dict:
    result = {
        "forms_found": 0,
        "password_fields": 0,
        "post_forms": 0,
        "insecure_form_actions": 0,
        "login_forms_using_get": 0,
        "csrf_token_like_fields": 0,
        "multipart_forms": 0,
    }

    if not BS4_AVAILABLE:
        return result

    try:
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        result["forms_found"] = len(forms)

        for form in forms:
            method = (form.get("method") or "").lower()
            action = (form.get("action") or "").strip().lower()
            enctype = (form.get("enctype") or "").lower()

            if method == "post":
                result["post_forms"] += 1
            if enctype == "multipart/form-data":
                result["multipart_forms"] += 1

            password_inputs = form.find_all("input", {"type": "password"})
            password_count = len(password_inputs)
            result["password_fields"] += password_count

            if action.startswith("http://"):
                result["insecure_form_actions"] += 1

            if password_count > 0 and method == "get":
                result["login_forms_using_get"] += 1

            hidden_inputs = form.find_all("input", {"type": "hidden"})
            for hidden in hidden_inputs:
                name = (hidden.get("name") or "").lower()
                if any(token_word in name for token_word in ["csrf", "token", "authenticity"]):
                    result["csrf_token_like_fields"] += 1

        return result
    except Exception:
        return result


def discover_resources(response, base_url: str) -> dict:
    result = {
        "page_title": "Not Found",
        "content_length": len(response.text) if response is not None else 0,
        "script_count": 0,
        "stylesheet_count": 0,
        "iframe_count": 0,
        "external_domains": set(),
        "javascript_files": [],
        "interesting_js_paths": [],
        "meta_generator": "Not Found",
    }

    if not BS4_AVAILABLE or response is None:
        result["external_domains"] = []
        return result

    try:
        soup = BeautifulSoup(response.text, "html.parser")

        title_tag = soup.find("title")
        if title_tag and title_tag.text.strip():
            result["page_title"] = title_tag.text.strip()[:60]

        generator_tag = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
        if generator_tag and generator_tag.get("content"):
            result["meta_generator"] = generator_tag.get("content", "")[:60]

        scripts = soup.find_all("script", src=True)
        links = soup.find_all("link", href=True)
        iframes = soup.find_all("iframe")

        result["script_count"] = len(scripts)
        result["stylesheet_count"] = sum(
            1 for link in links if (link.get("rel") and "stylesheet" in [r.lower() for r in link.get("rel")])
        )
        result["iframe_count"] = len(iframes)

        base_domain = urlparse(base_url).netloc.lower()

        for script in scripts:
            src = script.get("src", "").strip()
            if not src:
                continue

            full_src = urljoin(base_url, src)
            result["javascript_files"].append(full_src[:90])

            parsed = urlparse(full_src)
            domain = parsed.netloc.lower()
            if domain and domain != base_domain:
                result["external_domains"].add(domain)

            lowered = full_src.lower()
            if any(word in lowered for word in INTERESTING_JS_TERMS):
                result["interesting_js_paths"].append(full_src[:90])

        for iframe in iframes:
            src = iframe.get("src", "").strip()
            if src:
                full_src = urljoin(base_url, src)
                parsed = urlparse(full_src)
                domain = parsed.netloc.lower()
                if domain and domain != base_domain:
                    result["external_domains"].add(domain)

        result["external_domains"] = sorted(list(result["external_domains"]))[:10]
        result["interesting_js_paths"] = result["interesting_js_paths"][:10]
        return result

    except Exception:
        result["external_domains"] = []
        return result


def detect_mixed_content(response, final_url: str) -> bool:
    try:
        if final_url.lower().startswith("https://"):
            lowered = response.text.lower()
            return 'src="http://' in lowered or "src='http://" in lowered or 'href="http://' in lowered or "href='http://" in lowered
    except Exception:
        pass
    return False


# =========================
# DISCOVERY CHECKS
# =========================
def check_sensitive_paths(base_url: str) -> list:
    findings = []

    for path in COMMON_SENSITIVE_PATHS:
        full_url = urljoin(base_url, path)
        response = fetch_url(full_url, allow_redirects=True, method="GET")

        if response and response.status_code in [200, 401, 403]:
            findings.append({
                "path": path,
                "status": response.status_code
            })

    return findings


def classify_discovered_surfaces(paths: list) -> dict:
    result = {
        "login_surface": [],
        "admin_surface": [],
        "backup_surface": [],
        "other_surface": []
    }

    for item in paths:
        path = item["path"]

        if path in LOGIN_HINT_PATHS:
            result["login_surface"].append(item)
        elif path in ADMIN_HINT_PATHS:
            result["admin_surface"].append(item)
        elif path in BACKUP_HINT_PATHS:
            result["backup_surface"].append(item)
        else:
            result["other_surface"].append(item)

    return result


def detect_waf_or_cdn(response) -> list:
    findings = []
    if response is None:
        return findings

    all_headers_text = " ".join([f"{k}:{v}" for k, v in response.headers.items()]).lower()

    for hint, name in WAF_HINT_HEADERS.items():
        if hint in all_headers_text and name not in findings:
            findings.append(name)

    if response.status_code == 429 and "Rate Limiting / WAF Behavior" not in findings:
        findings.append("Rate Limiting / WAF Behavior")

    return findings


def inspect_tls_certificate(parsed_url) -> dict:
    result = {
        "https_enabled": False,
        "certificate_obtained": False,
        "subject": "Unknown",
        "issuer": "Unknown",
        "not_before": "Unknown",
        "not_after": "Unknown",
        "self_signed": "Unknown",
        "tls_error": "None",
    }

    if parsed_url.scheme.lower() != "https":
        return result

    host = parsed_url.hostname
    port = parsed_url.port or 443
    result["https_enabled"] = True

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        result["certificate_obtained"] = True

        subject = cert.get("subject", [])
        issuer = cert.get("issuer", [])

        def flatten_name(name_parts):
            items = []
            for item in name_parts:
                for key, value in item:
                    items.append(f"{key}={value}")
            return ", ".join(items) if items else "Unknown"

        result["subject"] = flatten_name(subject)[:70]
        result["issuer"] = flatten_name(issuer)[:70]
        result["not_before"] = cert.get("notBefore", "Unknown")
        result["not_after"] = cert.get("notAfter", "Unknown")
        result["self_signed"] = "YES" if result["subject"] == result["issuer"] else "NO"

    except Exception as exc:
        result["tls_error"] = str(exc)[:70]

    return result


def inspect_robots_txt(base_url: str) -> dict:
    result = {
        "found": False,
        "disallow_count": 0,
        "interesting_lines": []
    }

    robots_url = urljoin(base_url, "/robots.txt")
    response = fetch_url(robots_url, allow_redirects=True, method="GET")
    if not response or response.status_code != 200:
        return result

    result["found"] = True
    lines = response.text.splitlines()

    for line in lines:
        lowered = line.strip().lower()
        if lowered.startswith("disallow:"):
            result["disallow_count"] += 1
            if any(word in lowered for word in ["admin", "private", "backup", "test", "dev", "internal"]):
                result["interesting_lines"].append(line.strip()[:80])

    result["interesting_lines"] = result["interesting_lines"][:10]
    return result


def inspect_security_txt(base_url: str) -> dict:
    result = {
        "found": False,
        "contact_found": False,
        "policy_found": False
    }

    sec_url = urljoin(base_url, "/.well-known/security.txt")
    response = fetch_url(sec_url, allow_redirects=True, method="GET")
    if not response or response.status_code != 200:
        return result

    result["found"] = True
    lowered = response.text.lower()
    if "contact:" in lowered:
        result["contact_found"] = True
    if "policy:" in lowered:
        result["policy_found"] = True

    return result


# =========================
# MAIN ANALYSIS
# =========================
def analyze_website(target: str) -> dict:
    result = {
        "target": target,
        "normalized_url": normalize_url(target),
        "final_url": "-",
        "scheme": "-",
        "status_code": "N/A",
        "redirected": False,
        "redirect_chain": [],
        "server_header": "Not Disclosed",
        "x_powered_by": "Not Disclosed",
        "security_headers": {},
        "cookie_flags": {},
        "directory_listing": False,
        "forms": {},
        "sensitive_paths": [],
        "surface_groups": {},
        "waf_hints": [],
        "resources": {},
        "tls_info": {},
        "mixed_content": False,
        "robots_info": {},
        "security_txt_info": {},
        "resolved_ip": "Resolution Failed",
        "reverse_dns": "Not Found",
        "geo_info": {},
        "risk_categories": {
            "Transport Security": 0,
            "Header Security": 0,
            "Application Exposure": 0,
            "Content / Recon Findings": 0,
            "Session / Cookie Security": 0,
        },
        "risk_score": 0,
        "risk_level": "Low"
    }

    response = fetch_url(result["normalized_url"])
    if not response:
        result["risk_score"] = 100
        result["risk_level"] = "High"
        return result

    result["final_url"] = response.url
    parsed = urlparse(response.url)
    result["scheme"] = parsed.scheme.upper()
    result["status_code"] = str(response.status_code)
    result["redirected"] = response.history != []
    result["redirect_chain"] = build_redirect_chain(response)

    hostname = parsed.hostname or ""
    resolved_ip = resolve_hostname(hostname)
    result["resolved_ip"] = resolved_ip
    result["reverse_dns"] = reverse_dns_lookup(resolved_ip) if resolved_ip != "Resolution Failed" else "Not Found"
    result["geo_info"] = get_ip_geolocation(resolved_ip) if resolved_ip != "Resolution Failed" else {
        "country": "-", "region": "-", "city": "-", "timezone": "-", "isp": "-", "note": "No IP"
    }

    result["server_header"] = response.headers.get("Server", "Not Disclosed")
    result["x_powered_by"] = response.headers.get("X-Powered-By", "Not Disclosed")

    result["security_headers"] = check_security_headers(response)
    result["cookie_flags"] = check_cookie_flags(response)
    result["directory_listing"] = check_directory_listing(response)
    result["forms"] = check_forms(response)
    result["sensitive_paths"] = check_sensitive_paths(response.url)
    result["surface_groups"] = classify_discovered_surfaces(result["sensitive_paths"])
    result["waf_hints"] = detect_waf_or_cdn(response)
    result["resources"] = discover_resources(response, response.url)
    result["tls_info"] = inspect_tls_certificate(parsed)
    result["mixed_content"] = detect_mixed_content(response, response.url)
    result["robots_info"] = inspect_robots_txt(response.url)
    result["security_txt_info"] = inspect_security_txt(response.url)

    # Risk scoring
    if result["scheme"] != "HTTPS":
        result["risk_categories"]["Transport Security"] += 20

    tls_error = result["tls_info"].get("tls_error", "None")
    if result["scheme"] == "HTTPS" and tls_error != "None":
        result["risk_categories"]["Transport Security"] += 15

    if result["tls_info"].get("self_signed") == "YES":
        result["risk_categories"]["Transport Security"] += 15

    if result["mixed_content"]:
        result["risk_categories"]["Transport Security"] += 10

    for _, present in result["security_headers"].items():
        if not present:
            result["risk_categories"]["Header Security"] += 7

    if result["server_header"] != "Not Disclosed":
        result["risk_categories"]["Application Exposure"] += 10

    if result["x_powered_by"] != "Not Disclosed":
        result["risk_categories"]["Application Exposure"] += 10

    if result["directory_listing"]:
        result["risk_categories"]["Application Exposure"] += 20

    if result["forms"].get("insecure_form_actions", 0) > 0:
        result["risk_categories"]["Application Exposure"] += 15

    if result["forms"].get("login_forms_using_get", 0) > 0:
        result["risk_categories"]["Application Exposure"] += 15

    if result["forms"].get("password_fields", 0) > 0 and result["forms"].get("csrf_token_like_fields", 0) == 0:
        result["risk_categories"]["Application Exposure"] += 8

    if len(result["sensitive_paths"]) > 0:
        result["risk_categories"]["Content / Recon Findings"] += min(len(result["sensitive_paths"]) * 5, 25)

    if len(result["resources"].get("interesting_js_paths", [])) > 0:
        result["risk_categories"]["Content / Recon Findings"] += 10

    if result["robots_info"].get("found") and result["robots_info"].get("interesting_lines"):
        result["risk_categories"]["Content / Recon Findings"] += 8

    if len(result["waf_hints"]) > 0:
        result["risk_categories"]["Content / Recon Findings"] += 2

    if result["cookie_flags"].get("cookie_present", False):
        if not result["cookie_flags"].get("secure_flag", False):
            result["risk_categories"]["Session / Cookie Security"] += 8
        if not result["cookie_flags"].get("httponly_flag", False):
            result["risk_categories"]["Session / Cookie Security"] += 8
        if not result["cookie_flags"].get("samesite_flag", False):
            result["risk_categories"]["Session / Cookie Security"] += 6

    result["risk_score"] = sum(result["risk_categories"].values())

    score = result["risk_score"]
    if score >= 60:
        result["risk_level"] = "High"
    elif score >= 30:
        result["risk_level"] = "Medium"
    else:
        result["risk_level"] = "Low"

    return result


# =========================
# RENDERING
# =========================
def render_summary_table(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Web Security Summary:" + Colors.RESET)

    border = "+------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^25}|{'Status':^40}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    risk_color = Colors.GREEN
    if result["risk_level"] == "Medium":
        risk_color = Colors.YELLOW
    elif result["risk_level"] == "High":
        risk_color = Colors.RED

    rows = [
        ("Final URL", result["final_url"][:40], Colors.GREEN),
        ("Scheme", result["scheme"], Colors.CYAN),
        ("HTTP Status", result["status_code"], Colors.WHITE),
        ("Redirected", "YES" if result["redirected"] else "NO", Colors.YELLOW if result["redirected"] else Colors.GREEN),
        ("Resolved IP", str(result["resolved_ip"])[:40], Colors.YELLOW),
        ("Risk Score", str(result["risk_score"]), risk_color),
        ("Risk Level", result["risk_level"], risk_color),
    ]

    for label, value, color in rows:
        print(
            Colors.WHITE + "|" +
            f"{label:<25}" +
            "|" +
            color + f"{value:^40}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_headers_table(headers_result: dict):
    print("\n" + Colors.MAGENTA + Colors.BOLD + "Security Headers Check:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Header Check':^38}|{'Status':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    for label, present in headers_result.items():
        status_text = "PASS" if present else "FAIL"
        status_color = Colors.GREEN if present else Colors.RED

        print(
            Colors.WHITE + "|" +
            f"{label:<38}" +
            "|" +
            status_color + f"{status_text:^15}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_cookie_table(cookie_result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Cookie Security Check:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^38}|{'Status':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("Cookie Present", "YES" if cookie_result.get("cookie_present") else "NO", Colors.GREEN if cookie_result.get("cookie_present") else Colors.YELLOW),
        ("Secure Flag", "PASS" if cookie_result.get("secure_flag") else "FAIL", Colors.GREEN if cookie_result.get("secure_flag") else Colors.RED),
        ("HttpOnly Flag", "PASS" if cookie_result.get("httponly_flag") else "FAIL", Colors.GREEN if cookie_result.get("httponly_flag") else Colors.RED),
        ("SameSite Flag", "PASS" if cookie_result.get("samesite_flag") else "FAIL", Colors.GREEN if cookie_result.get("samesite_flag") else Colors.RED),
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


def render_exposure_table(result: dict):
    print("\n" + Colors.YELLOW + Colors.BOLD + "Technology / Exposure Check:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^25}|{'Status':^28}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("Server Header", result["server_header"][:28]),
        ("X-Powered-By", result["x_powered_by"][:28]),
        ("Directory Listing", "YES" if result["directory_listing"] else "NO"),
        ("Forms Found", str(result["forms"].get("forms_found", 0))),
        ("Password Fields", str(result["forms"].get("password_fields", 0))),
        ("POST Forms", str(result["forms"].get("post_forms", 0))),
        ("Multipart Forms", str(result["forms"].get("multipart_forms", 0))),
        ("Mixed Content", "YES" if result["mixed_content"] else "NO"),
    ]

    for label, value in rows:
        value_text = str(value)[:28]
        print(
            Colors.WHITE + "|" +
            f"{label:<25}" +
            "|" +
            Colors.YELLOW + f"{value_text:^28}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_tls_table(tls_info: dict):
    print("\n" + Colors.MAGENTA + Colors.BOLD + "TLS / Certificate Analysis:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^25}|{'Status':^28}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("HTTPS Enabled", "YES" if tls_info.get("https_enabled") else "NO"),
        ("Certificate Retrieved", "YES" if tls_info.get("certificate_obtained") else "NO"),
        ("Self Signed", tls_info.get("self_signed", "Unknown")),
        ("Issuer", str(tls_info.get("issuer", "Unknown"))[:28]),
        ("Valid From", str(tls_info.get("not_before", "Unknown"))[:28]),
        ("Valid Until", str(tls_info.get("not_after", "Unknown"))[:28]),
        ("TLS Error", str(tls_info.get("tls_error", "None"))[:28]),
    ]

    for label, value in rows:
        value_text = str(value)[:28]
        color = Colors.YELLOW
        if label in ["HTTPS Enabled", "Certificate Retrieved"]:
            color = Colors.GREEN if value == "YES" else Colors.RED
        if label == "Self Signed":
            color = Colors.RED if value == "YES" else Colors.GREEN
        if label == "TLS Error":
            color = Colors.GREEN if value == "None" else Colors.RED

        print(
            Colors.WHITE + "|" +
            f"{label:<25}" +
            "|" +
            color + f"{value_text:^28}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_network_context(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Resolved Network Context:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^25}|{'Status':^28}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    geo = result["geo_info"]

    rows = [
        ("Resolved IP", str(result["resolved_ip"])[:28]),
        ("Reverse DNS", str(result["reverse_dns"])[:28]),
        ("Country", str(geo.get("country", "-"))[:28]),
        ("Region", str(geo.get("region", "-"))[:28]),
        ("City", str(geo.get("city", "-"))[:28]),
        ("Timezone", str(geo.get("timezone", "-"))[:28]),
        ("ISP", str(geo.get("isp", "-"))[:28]),
        ("GeoIP Note", str(geo.get("note", "-"))[:28]),
    ]

    for label, value in rows:
        print(
            Colors.WHITE + "|" +
            f"{label:<25}" +
            "|" +
            Colors.YELLOW + f"{value:^28}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_sensitive_paths_table(paths: list):
    print("\n" + Colors.MAGENTA + Colors.BOLD + "Sensitive Path Discovery:" + Colors.RESET)

    border = "+-----------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^6}|{'Path':^25}|{'HTTP Status':^20}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    if not paths:
        print(
            Colors.WHITE + "|" +
            f"{'-':^6}" +
            "|" +
            Colors.GREEN + f"{'None Found':^25}" +
            Colors.WHITE + "|" +
            f"{'-':^20}" +
            "|" +
            Colors.RESET
        )
    else:
        for idx, item in enumerate(paths, start=1):
            path = item["path"][:25]
            status = str(item["status"])
            color = Colors.YELLOW
            if status == "200":
                color = Colors.RED
            elif status in ["401", "403"]:
                color = Colors.MAGENTA

            print(
                Colors.WHITE + "|" +
                f"{str(idx):^6}" +
                "|" +
                Colors.YELLOW + f"{path:<25}" +
                Colors.WHITE + "|" +
                color + f"{status:^20}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_surface_summary(surface_groups: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Surface Classification Summary:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Surface Type':^38}|{'Count':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("Login Surface", len(surface_groups.get("login_surface", [])), Colors.YELLOW),
        ("Admin Surface", len(surface_groups.get("admin_surface", [])), Colors.RED),
        ("Backup Surface", len(surface_groups.get("backup_surface", [])), Colors.MAGENTA),
        ("Other Surface", len(surface_groups.get("other_surface", [])), Colors.GREEN),
    ]

    for label, count, color in rows:
        print(
            Colors.WHITE + "|" +
            f"{label:<38}" +
            "|" +
            color + f"{str(count):^15}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_resource_table(resources: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Page / Resource Fingerprint:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^25}|{'Status':^28}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("Page Title", resources.get("page_title", "Not Found")),
        ("Meta Generator", resources.get("meta_generator", "Not Found")),
        ("Content Length", str(resources.get("content_length", 0))),
        ("Script Count", str(resources.get("script_count", 0))),
        ("Stylesheets", str(resources.get("stylesheet_count", 0))),
        ("iFrames", str(resources.get("iframe_count", 0))),
        ("External Domains", str(len(resources.get("external_domains", [])))),
        ("Interesting JS Paths", str(len(resources.get("interesting_js_paths", [])))),
    ]

    for label, value in rows:
        value_text = str(value)[:28]
        print(
            Colors.WHITE + "|" +
            f"{label:<25}" +
            "|" +
            Colors.YELLOW + f"{value_text:^28}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_redirect_chain(chain: list):
    print("\n" + Colors.MAGENTA + Colors.BOLD + "Redirect Chain:" + Colors.RESET)

    border = "+-----------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^6}|{'Redirect Step':^46}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    if not chain:
        print(
            Colors.WHITE + "|" +
            f"{'-':^6}" +
            "|" +
            Colors.GREEN + f"{'No Redirect Chain':^46}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )
    else:
        for idx, item in enumerate(chain, start=1):
            text = item[:46]
            print(
                Colors.WHITE + "|" +
                f"{str(idx):^6}" +
                "|" +
                Colors.YELLOW + f"{text:<46}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_list_table(title: str, items: list, empty_text: str):
    print("\n" + Colors.MAGENTA + Colors.BOLD + title + ":" + Colors.RESET)

    border = "+-----------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^6}|{'Value':^46}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    if not items:
        print(
            Colors.WHITE + "|" +
            f"{'-':^6}" +
            "|" +
            Colors.GREEN + f"{empty_text:^46}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )
    else:
        for idx, item in enumerate(items, start=1):
            text = str(item)[:46]
            print(
                Colors.WHITE + "|" +
                f"{str(idx):^6}" +
                "|" +
                Colors.YELLOW + f"{text:<46}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_policy_files(robots_info: dict, security_txt_info: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Policy / Security File Review:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^38}|{'Status':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("robots.txt Found", "YES" if robots_info.get("found") else "NO", Colors.GREEN if robots_info.get("found") else Colors.YELLOW),
        ("robots Interesting Lines", str(len(robots_info.get("interesting_lines", []))), Colors.YELLOW),
        ("security.txt Found", "YES" if security_txt_info.get("found") else "NO", Colors.GREEN if security_txt_info.get("found") else Colors.YELLOW),
        ("security.txt Contact", "YES" if security_txt_info.get("contact_found") else "NO", Colors.GREEN if security_txt_info.get("contact_found") else Colors.YELLOW),
        ("security.txt Policy", "YES" if security_txt_info.get("policy_found") else "NO", Colors.GREEN if security_txt_info.get("policy_found") else Colors.YELLOW),
    ]

    for label, value, color in rows:
        print(
            Colors.WHITE + "|" +
            f"{label:<38}" +
            "|" +
            color + f"{str(value):^15}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_risk_categories_table(risk_categories: dict):
    print("\n" + Colors.YELLOW + Colors.BOLD + "Risk Categories:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Category':^38}|{'Score':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    for label, value in risk_categories.items():
        color = Colors.GREEN
        if value >= 15:
            color = Colors.RED
        elif value >= 8:
            color = Colors.YELLOW

        print(
            Colors.WHITE + "|" +
            f"{label:<38}" +
            "|" +
            color + f"{str(value):^15}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_recommendations(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Recommendations:" + Colors.RESET)

    border = "+-----------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^6}|{'Recommendation':^46}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    recommendations = []

    if result["scheme"] != "HTTPS":
        recommendations.append("Enable HTTPS across the site.")

    if result["mixed_content"]:
        recommendations.append("Remove mixed-content HTTP resources.")

    if any(not present for present in result["security_headers"].values()):
        recommendations.append("Add missing security headers.")

    if result["server_header"] != "Not Disclosed":
        recommendations.append("Reduce server banner disclosure.")

    if result["x_powered_by"] != "Not Disclosed":
        recommendations.append("Hide X-Powered-By exposure.")

    if result["directory_listing"]:
        recommendations.append("Disable directory listing.")

    if result["forms"].get("insecure_form_actions", 0) > 0:
        recommendations.append("Use HTTPS form actions only.")

    if result["forms"].get("login_forms_using_get", 0) > 0:
        recommendations.append("Avoid GET for login forms.")

    if result["forms"].get("password_fields", 0) > 0 and result["forms"].get("csrf_token_like_fields", 0) == 0:
        recommendations.append("Review CSRF protection on forms.")

    if result["cookie_flags"].get("cookie_present", False):
        if not result["cookie_flags"].get("secure_flag", False):
            recommendations.append("Set Secure on cookies.")
        if not result["cookie_flags"].get("httponly_flag", False):
            recommendations.append("Set HttpOnly on cookies.")
        if not result["cookie_flags"].get("samesite_flag", False):
            recommendations.append("Set SameSite on cookies.")

    if result["sensitive_paths"]:
        recommendations.append("Restrict access to sensitive paths.")

    if result["tls_info"].get("self_signed") == "YES":
        recommendations.append("Replace self-signed certificate.")

    if result["tls_info"].get("tls_error") != "None":
        recommendations.append("Review TLS/certificate configuration.")

    if result["robots_info"].get("interesting_lines"):
        recommendations.append("Review robots.txt for sensitive references.")

    if not recommendations:
        recommendations.append("No immediate issues found.")

    deduped = []
    for item in recommendations:
        if item not in deduped:
            deduped.append(item)

    for idx, item in enumerate(deduped[:8], start=1):
        text = item[:46]
        print(
            Colors.WHITE + "|" +
            f"{str(idx):^6}" +
            "|" +
            Colors.YELLOW + f"{text:<46}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


# =========================
# MAIN
# =========================
def main():
    print_banner()

    print_message(Colors.BLUE + "[i] Mode        : Web Attack Surface Mapping")
    print_message(Colors.BLUE + "[i] Input Type  : Website URL")
    print_message(Colors.BLUE + "[i] Detection   : Safe Exposure / Header / TLS / Surface Checks")
    print_message(Colors.BLUE + "[i] Features    : Redirect Chain / Robots.txt / Security.txt / GeoIP / Surface Groups\n")

    try:
        target = ask_input("Enter Website URL or Domain : ").strip()

        if not target:
            print_message(Colors.RED + "[!] No Target Provided.")
            sys.exit(1)

        print()
        print_message(Colors.YELLOW + "[-] Scanning Website ...")
        print_message(Colors.YELLOW + "[-] Mapping Exposed Surfaces and Hardening Signals ...\n")

        result = analyze_website(target)

        render_summary_table(result)
        render_network_context(result)
        render_risk_categories_table(result["risk_categories"])
        render_headers_table(result["security_headers"])
        render_cookie_table(result["cookie_flags"])
        render_exposure_table(result)
        render_tls_table(result["tls_info"])
        render_redirect_chain(result["redirect_chain"])
        render_policy_files(result["robots_info"], result["security_txt_info"])
        render_sensitive_paths_table(result["sensitive_paths"])
        render_surface_summary(result["surface_groups"])
        render_resource_table(result["resources"])
        render_list_table("WAF / CDN Hints", result["waf_hints"], "None Detected")
        render_list_table("External Domains", result["resources"].get("external_domains", []), "None Found")
        render_list_table("Interesting JavaScript Paths", result["resources"].get("interesting_js_paths", []), "None Found")
        render_list_table("robots.txt Interesting Lines", result["robots_info"].get("interesting_lines", []), "None Found")
        render_recommendations(result)

    except KeyboardInterrupt:
        print_message("\n" + Colors.RED + "[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as exc:
        print_message(Colors.RED + f"[!] Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    time.sleep(60)
