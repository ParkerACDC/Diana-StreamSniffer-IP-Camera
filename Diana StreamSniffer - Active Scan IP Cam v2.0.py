import requests
import socket
import sys
import warnings
import ipaddress
import base64
import time
import hashlib
import re
import concurrent.futures
import ftplib
from requests.packages.urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

if sys.stdout.isatty():
    R, G, C, W, Y, M, B = '\033[31m', '\033[32m', '\033[36m', '\033[0m', '\033[33m', '\033[35m', '\033[34m'
else:
    R = G = C = W = Y = M = B = ''

BANNER = rf"""{C}
=========================================================================

██████╗ ██╗ █████╗ ███╗   ██╗ █████╗ 
██╔══██╗██║██╔══██╗████╗  ██║██╔══██╗
██║  ██║██║███████║██╔██╗ ██║███████║
██║  ██║██║██╔══██║██║╚██╗██║██╔══██║
██████╔╝██║██║  ██║██║ ╚████║██║  ██║
╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝

{G} > Diana StreamSniffer:
{G} > >>> Automated enumeration & credential scanner for IP cameras
{Y} > By:{W} Peter Layetta
{Y} > Version:{W} 2.0
{C}======================================================================{W}
"""

#Common IP camera ports
COMMON_PORTS = [
    21, 22, 23,  #FTP, SSH, Telnet
    80, 81, 82, 85, 443, 8080, 8443, 8000, 8001, 8008, 8888, 9000,
    554, 555, 8554, 10554, 5554,
    1935, 1936,
    37777, 37778, 3702, 8100, 5000, 6000, 37779
]

KNOWN_PROTOCOLS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet"
}

HTTPS_PORTS = [443, 8443, 8444]
HEADERS = {'User-Agent': 'Local-Network-Scanner/1.0'}
PORT_SCAN_TIMEOUT = 2.0
HTTP_TIMEOUT = 5
RTSP_TIMEOUT = 4
FTP_TIMEOUT = 5

COMMON_PATHS = [
    "/", "/admin", "/login", "/viewer", "/video", "/stream", 
    "/live", "/snapshot", "/config", "/setup", "/cgi-bin/",
    "/stream1", "/stream2", "/ch0.h264", "/live1.sdp", "/h264_stream", "/11", "/login.htm",
    "/11", "/1", "/live/ch00_0", "/live/ch00_1", "/h264_stream", "/onvif1", "/1/cif",
]

DEFAULT_CREDENTIALS = [
    ("666666", "666666"),
    ("888888", "888888"),
    ("admin", ""),
    ("admin", "123"),
    ("admin", "jvc"),
    ("admin", "1111"),
    ("admin", "1234"),
    ("admin", "4321"),
    ("admin", "9999"),
    ("admin", "pass"),
    ("admin", "wbox"),
    ("admin", "12345"),
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "666666"),
    ("admin", "888888"),
    ("admin", "meinsm"),
    ("admin", "1111111"),
    ("admin", "wbox123"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "fliradmin"),
    ("admin1", "password"),
    ("Administrator", ""),
    ("administrator", "1234"),
    ("Camera", "admin pass"),
    ("Dinion", ""),
    ("guest", "guest"),
    ("Recorder", "1111"),
    ("Recorder", "admin"),
    ("root", ""),
    ("root", "4321"),
    ("root", "ikwb"),
    ("root", "ikwd"),
    ("root", "pass"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "12345"),
    ("root", "admin"),
    ("root", "camera"),
    ("root", "system"),
    ("service", "service"),
    ("supervisor", "supervisor"),
    ("ubnt", "ubnt"),
    ("user", "user")
]

def validate_ip(target_ip):
    # No no ip public yh :D
    try:
        ip = ipaddress.ip_address(target_ip)
        if not ip.is_private:
            print(f"{R}[!] Error: Target {target_ip} is a public IP. This tool is restricted for private/local networks only.{W}")
            return False
        return True
    except ValueError:
        print(f"{R}[!] Invalid IP address format.{W}")
        return False

def parse_ip_port(input_str):
    input_str = input_str.strip()
    if ':' in input_str:
        parts = input_str.rsplit(':', 1)
        if len(parts) == 2:
            ip_str, port_str = parts
            try:
                port = int(port_str)
                if 1 <= port <= 65535:
                    return ip_str.strip(), port
            except ValueError:
                pass
            print(f"{R}[!] Invalid port.{W}")
            return None, None
    return input_str, None

def get_protocol(port):
    return "https" if port in HTTPS_PORTS else "http"

def probe_rtsp(ip, port):
    #Actively probe for RTSP protocol response
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(PORT_SCAN_TIMEOUT)
            if s.connect_ex((ip, port)) != 0:
                return False
            request = (f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n").encode()
            s.sendall(request)
            data = s.recv(1024)
            if data and b"RTSP/1.0" in data:
                return True
    except Exception:
        pass
    return False

def check_single_port(ip, port):
    # Scanning with protocol identification
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(PORT_SCAN_TIMEOUT)
            if sock.connect_ex((ip, port)) == 0:
                
                # check to prevent false label http
                if port in KNOWN_PROTOCOLS:
                    proto = KNOWN_PROTOCOLS[port]
                    is_rtsp = False
                else:
                    is_rtsp = probe_rtsp(ip, port)
                    proto = "RTSP" if is_rtsp else get_protocol(port).upper()
                
                print(f"  ✅ [OPEN] {port}/tcp ({proto})")
                return port, is_rtsp
    except Exception:
        pass
    return None, False

def scan_ports(ip, additional_ports=None):
    # Concurrent port scanning + feature for tracking progress and port list
    if additional_ports:
        ports_to_scan = list(set(additional_ports))
    else:
        ports_to_scan = list(set(COMMON_PORTS))
        
    total_ports = len(ports_to_scan)
    
    print(f"\n🔍 {C}Scanning ports on {ip}...{W}")
    print(f"{Y}   Scanning {total_ports} ports. This may take a while...{W}")
    
    sorted_ports = sorted(ports_to_scan)
    total = len(sorted_ports)
    if total <= 30:
        print(f"{B}    Target Ports: {W}{', '.join(map(str, sorted_ports))}\n")
    else:
        sample = ", ".join(str(p) for p in sorted_ports[:20])
        print(f"{B}    Target Ports: {W}{sample}, ... ({total-20} more)\n")
    
    open_ports = []
    rtsp_ports = []
    scanned_count = 0
    
    update_interval = 5 if total_ports <= 50 else 50
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(check_single_port, ip, port): port for port in ports_to_scan}
        
        for future in concurrent.futures.as_completed(future_to_port):
            scanned_count += 1
            result, is_rtsp = future.result()
            
            if result:
                open_ports.append(result)
                if is_rtsp:
                    rtsp_ports.append(result)
            
            if scanned_count % update_interval == 0 and scanned_count < total_ports:
                print(f"  Scanned {scanned_count}/{total_ports} ports...")

    print(f"\n{Y}Scan completed: {scanned_count} ports checked, {len(open_ports)} ports open.{W}")
    return sorted(open_ports), sorted(rtsp_ports)

def check_generic_http(ip, open_ports):
    # HTTP/HTTPS checking to detect login portals or basic vid interfaces
    print(f"\n{C}Checking HTTP/HTTPS interfaces:{W}")
    
    # Exclude RTSP, RTMP, and other standart ports from HTTP checking
    web_ports = [p for p in open_ports if p not in [21, 22, 23, 554, 8554, 10554, 1935]]
    
    if not web_ports:
        print("  ❌ No standard web ports open to check.")
        return

    found_any = False
    for port in web_ports[:5]:
        protocol = get_protocol(port)
        url = f"{protocol}://{ip}:{port}/"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            server = resp.headers.get("Server", "Unknown")
            print(f"  ℹ️ {url} - Status: {resp.status_code} | Server: {server}")
            found_any = True
        except Exception:
            pass
            
    if not found_any:
        print("  ❌ No HTTP responses received from open web ports.")

def check_login_pages(ip, open_ports):
    #Scan for common authentication endpoints 
    print(f"\n{C}Scanning for common authentication pages:{W}")
    web_ports = [p for p in open_ports if p not in [21, 22, 23, 554, 8554, 10554, 1935]]
    
    if not web_ports:
        print("  ❌ Skipping: No web ports available for auth scanning.")
        return

    found_urls = []
    
    def check_path(port, path):
        url = f"{get_protocol(port)}://{ip}:{port}{path}"
        try:
            resp = requests.head(url, headers=HEADERS, timeout=HTTP_TIMEOUT, verify=False)
            # If server no no to HEAD requests, fallback to GET
            if resp.status_code == 405:
                resp = requests.get(url, headers=HEADERS, timeout=HTTP_TIMEOUT, verify=False)
            if resp.status_code in [200, 401, 403]:
                print(f"  ✅ Found endpoint: {url} (Status: {resp.status_code})")
                found_urls.append(url)
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        for port in web_ports:
            for path in COMMON_PATHS:
                executor.submit(check_path, port, path)
                
    if not found_urls:
        print("  ❌ No authentication pages detected on open web ports.")

def check_rtsp_auth_required(ip, port):
    # Check if the RTSP stream requires password
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            if s.connect_ex((ip, port)) != 0:
                return True
            
            request = (f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n").encode()
            s.sendall(request)
            data = s.recv(1024).decode(errors="ignore")
            
            if "200 OK" in data:
                return False
    except Exception:
        pass
    return True

def parse_digest_challenge(header):
    parts = {}
    for key in ['realm', 'nonce', 'opaque', 'qop']:
        m = re.search(rf'{key}="([^"]+)"', header)
        if m:
            parts[key] = m.group(1)
    return parts

def build_digest_response(username, password, method, uri, challenge):
    realm = challenge.get('realm', '')
    nonce = challenge.get('nonce', '')
    qop = challenge.get('qop', 'auth')
    opaque = challenge.get('opaque', '')
    nc = "00000001"
    cnonce = hashlib.md5(str(time.time()).encode()).hexdigest()[:16]

    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    if qop:
        response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
        auth = (f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
                f'uri="{uri}", response="{response}", qop={qop}, nc={nc}, cnonce="{cnonce}"')
    else:
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        auth = (f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
                f'uri="{uri}", response="{response}"')
    if opaque:
        auth += f', opaque="{opaque}"'
    return auth

def test_rtsp_credentials(ip, port, username, password):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(RTSP_TIMEOUT)
            if s.connect_ex((ip, port)) != 0:
                return False

            # Probe for auth method
            req1 = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode()
            s.sendall(req1)
            data = s.recv(2048).decode(errors="ignore")

            if "200 OK" in data:
                return True

            # Try Basic Auth
            auth_b64 = base64.b64encode(f"{username}:{password}".encode()).decode()
            req_basic = (f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                         f"Authorization: Basic {auth_b64}\r\nCSeq: 2\r\n\r\n").encode()
            s.sendall(req_basic)
            resp_basic = s.recv(2048).decode(errors="ignore")
            if "200 OK" in resp_basic:
                return True

            # Try Digest Auth if challenged
            if "Digest" in data and "401" in data:
                challenge = parse_digest_challenge(data)
                if challenge:
                    auth_hdr = build_digest_response(username, password, "OPTIONS", f"rtsp://{ip}:{port}/", challenge)
                    req_digest = (f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                                  f"Authorization: {auth_hdr}\r\nCSeq: 3\r\n\r\n").encode()
                    s.sendall(req_digest)
                    resp_digest = s.recv(2048).decode(errors="ignore")
                    if "200 OK" in resp_digest:
                        return True
    except Exception:
        pass
    return False

def test_http_credentials(ip, port, username, password):
    protocol = get_protocol(port)
    base_url = f"{protocol}://{ip}:{port}"

    # basic authentication at root
    try:
        r = requests.get(base_url + "/", auth=(username, password), headers=HEADERS, timeout=HTTP_TIMEOUT, verify=False)
        if r.status_code == 200:
            return "basic", f"{base_url}/"
    except Exception:
        pass

    # Form-based authentication on login pages
    login_paths = ["/login", "/login.htm", "/admin", "/"]
    for path in login_paths:
        try:
            url = base_url + path
            r = requests.get(url, headers=HEADERS, timeout=HTTP_TIMEOUT, verify=False)
            if r.status_code != 200:
                continue

            # Detect common form fields
            text = r.text.lower()
            if any(k in text for k in ['password', 'passwd', 'pwd', 'pass']):
                user_field, pass_field = None, None
                for candidate in ['username', 'user', 'uname', 'login', 'id', 'name', 'admin']:
                    if f'name="{candidate}"' in text or f"name='{candidate}'" in text or f'id="{candidate}"' in text:
                        user_field = candidate
                        break
                for candidate in ['password', 'passwd', 'pwd', 'pass', 'password1']:
                    if f'name="{candidate}"' in text or f"name='{candidate}'" in text or f'id="{candidate}"' in text:
                        pass_field = candidate
                        break

                if user_field and pass_field:
                    payload = {user_field: username, pass_field: password}
                    r2 = requests.post(url, data=payload, headers=HEADERS, timeout=HTTP_TIMEOUT, verify=False, allow_redirects=True)
                    # Success heuristics
                    if r2.status_code in {200, 302} and 'login' not in r2.url.lower():
                        if any(k in r2.text.lower() for k in ['logout', 'config', 'stream', 'live', 'camera']):
                            return "form", url
        except Exception:
            pass
    return None

def test_ftp_credentials(ip, port, username, password):
    ftp = None
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=FTP_TIMEOUT)
        ftp.login(user=username, passwd=password)
        return True
    except Exception:
        return False
    finally:
        try:
            if ftp:
                ftp.quit()
        except Exception:
            pass

def brute_force_defaults(ip, open_ports, rtsp_ports):
    #Test default credentials against open interfaces
    print(f"\n🔓 {C}Testing default credentials (Active Brute-force):{W}")
    found = False
    
    # Testing open FTP
    if 21 in open_ports:
        for user, pwd in DEFAULT_CREDENTIALS:
            if test_ftp_credentials(ip, 21, user, pwd):
                print(f"  ✅⚠️ Success [FTP]: {user}:{pwd} @ ftp://{ip}:21/")
                found = True
                break

    # Flag ssh and telnet
    if 22 in open_ports:
        print(f"  {Y}✅⚠️ [HIGH RISK] SSH (Port 22) is OPEN. Try manual access using ssh root@{ip}{W}")
    if 23 in open_ports:
        print(f"  {R}✅⚠️ [CRITICAL] Telnet (Port 23) is OPEN. Unencrypted terminal access. {W}")
    
    # Test RTSP
    for port in rtsp_ports:
        if not check_rtsp_auth_required(ip, port):
            print(f"  {R}🚨 [CRITICAL] RTSP is completely open! (No password required) @ rtsp://{ip}:{port}/{W}")
            found = True
            continue
            
        # If password required
        for user, pwd in DEFAULT_CREDENTIALS:
            if test_rtsp_credentials(ip, port, user, pwd):
                print(f"  ✅⚠️ Success [RTSP]: {user}:{pwd} @ rtsp://{ip}:{port}/")
                found = True
                break

    #Test HTTP or Web form
    web_ports = [p for p in open_ports if p not in rtsp_ports and p not in [21, 22, 23]][:3]
    for port in web_ports:
        if found: break
        for user, pwd in DEFAULT_CREDENTIALS:
            result = test_http_credentials(ip, port, user, pwd)
            if result:
                auth_type, url = result
                print(f"  ✅⚠️ Success [WEB/{auth_type.upper()}]: {user}:{pwd} @ {url}")
                found = True
                break
    if not found:
        print("  ❌ No default credentials worked.")

def detect_live_streams(ip, rtsp_ports):
    # Print generic stream paths based on founded open RTSP ports
    if not rtsp_ports:
        return
        
    print(f"\n{C}▶️ Potential RTSP Stream URLs (Test with VLC):{W}")
    generic_paths = ['/', '/live.sdp', '/h264', '/stream1', '/videoMain']
    
    for port in rtsp_ports:
        for path in generic_paths:
            print(f"     rtsp://{ip}:{port}{path}")

def main():
    try:
        print(BANNER)
        user_input = input(f"{G}[+] {C}Enter target local IP address or (IP:PORT): {W}").strip()
        
        target_ip, specified_port = parse_ip_port(user_input)
        if not target_ip or not validate_ip(target_ip):
            return

        additional = [specified_port] if specified_port else []
        open_ports, rtsp_ports = scan_ports(target_ip, additional)

        if not open_ports:
            print("\n[❌] No open ports found. Host may be down or strict firewall configuration.")
            return

        check_generic_http(target_ip, open_ports)
        check_login_pages(target_ip, open_ports)
        brute_force_defaults(target_ip, open_ports, rtsp_ports)
        detect_live_streams(target_ip, rtsp_ports)

        print("\n✅ Active scan completed")

    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()