**Automated Enumeration & Credential Scanner for IP Cameras 📸**

Diana StreamSniffer is a specialized network auditing tool designed to help administrators and security researchers actively probe and audit IP cameras on local networks. Developed as part of an academic thesis project, it automates the process of discovering camera services, fingerprinting open interfaces, enumerating common endpoints, and auditing devices against known default credential vulnerabilities.

To ensure responsible use, this tool is strictly limited to private/local network IP addresses only. Diana is the active scanning counterpart to Iris CamOracle, while Iris performs passive security and privacy evaluation through Deep Packet Inspection of PCAP files, Diana is designed for active reconnaissance and is typically used as a first step to map the target device's attack surface before passive analysis begins.


**Features:**
- Host Discovery: Verifies host availability via ICMP ping. If the host is unreachable (e.g., due to AP isolation or guest network mode), the user is presented with a force-scan option to continue port scanning regardless.
- Concurrent Port Scanning: Uses multi-threading via ThreadPoolExecutor to rapidly scan a curated list of common IP camera ports covering RTSP, HTTP/HTTPS, FTP, SSH, and Telnet, with real-time progress reporting.
- Protocol Identification: Accurately distinguishes between HTTP web servers and RTSP streams even on non-standard ports by actively sending RTSP OPTIONS probes and inspecting responses, preventing false protocol labeling.
- HTTP Interface Fingerprinting: Probes open web ports to retrieve HTTP status codes and Server header banners, providing quick identification of the camera's web interface type and software.
- Endpoint & Directory Enumeration: Actively fuzzes a curated list of common IP camera paths (e.g., /admin, /live, /cgi-bin/, /onvif1, /stream1) across all open web ports to identify exposed login portals, viewing pages, and administrative directories.
- Deep Credential Auditing: Tests a built-in list of common manufacturer default credentials across multiple services:
  > - RTSP: First checks whether the stream requires authentication at all. If protected, supports both Basic Auth and full Digest Auth challenge-response, including parsing of realm, nonce, qop, and opaque fields with     correct MD5 hash construction.
  > - HTTP: Uses form-detection heuristics to dynamically identify login field names (e.g., username, pwd) from HTTP 200 OK login pages, enabling credential testing against custom web interfaces beyond simple Basic Auth.
  > - FTP: Tests default credentials against open FTP services commonly left enabled by manufacturers.
  > - SSH & Telnet: Rather than brute-forcing, open SSH (port 22) and Telnet (port 23) are immediately flagged as HIGH RISK and CRITICAL respectively, with advisory output alerting the user to the presence of unencrypted or remotely accessible terminal services.
- Live Stream Extraction: Generates ready to test RTSP stream URLs across common stream paths for all confirmed open RTSP ports, formatted for direct use with VLC Media Player.

**Special?**
- Proper RTSP Digest Auth — Rather than relying on external libraries or guessing, Diana actively probes RTSP responses and constructs valid RFC-compliant MD5 Digest authentication headers on the fly, including qop=auth challenge handling.
- Dynamic Web Form Detection: Instead of only checking for HTTP 401 Unauthorized responses, Diana fetches HTTP 200 OK login pages, parses the HTML to identify dynamic input field names, and submits credentials against them — handling the custom web interfaces common in IP camera firmware.
- Smart Protocol Guard: Well-known non-HTTP ports (FTP, SSH, Telnet, RTSP) are explicitly excluded from HTTP interface checks, preventing false positives and keeping output clean.
- All-in-One Execution: Combines host discovery, concurrent port scanning, HTTP fingerprinting, endpoint fuzzing, and multi-protocol credential auditing into a single cohesive terminal workflow with no complex command-line flags required.

**Requirements 📝**
This tool relies primarily on Python standard libraries, minimizing external dependencies.
Dependencies:
- Python 3.12 (Developed and tested on this version)
- requests (pip install requests)

▶️ How to use:
1. Make sure the camera is connected yo your PC hotspot (for easier way to find out the camera's IP adress), or connected to Wifi's router (to find out what's the IP address try use router control panel like TP-Link Control / Huawei web page network configuration / etc).
2. Run the Diana tool nad enter the camera's IP address

The developer assumes no liability and is not responsible for any misuse, damage, or legal consequences caused by utilizing this tool :D
