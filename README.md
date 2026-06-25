**Automated Enumeration & Credential Scanner for IP Cameras
**
Diana StreamSniffer is a specialized network auditing tool designed to help administrators and researchers identify exposed IP cameras on local networks. Developed as part of an academic thesis project, 
it automates the process of discovering cameras, identifying open protocols, and auditing devices against common default credential vulnerabilities.

To ensure responsible use, this tool is limited to operate on private/local network IP addresses only.

**Note:** This is a sister tool to Iris. While Iris focuses on passive analysis via Deep Packet Inspection from PCAP Files, Diana is designed for active probing.


**Features:**
- Host Discovery: Verifies host availability via ICMP ping, with bypass options for devices hidden behind AP isolation.
- Concurrent Port Scanning: Uses multi-threading (ThreadPoolExecutor) to rapidly scan common IP camera ports (RTSP, HTTP/HTTPS, FTP, SSH, Telnet).
- Protocol Identification: Accurately distinguishes between standard HTTP web servers and RTSP streams, even on non-standard ports.
- Endpoint Enumeration: Actively maps out common login portals, viewing pages, and administrative directories.
- Deep Credential Auditing: Tests a built-in list of common manufacturer default credentials across multiple services:
- RTSP: Supports both Basic and complex Digest authentication challenge-response parsing.
- HTTP: Uses form-detection heuristics to dynamically identify and interact with login fields, going beyond simple Basic Auth.
- FTP: Tests common fallback protocols often left open by manufacturers.
- Live Stream Extraction: Generates ready-to-test VLC stream URLs for confirmed open RTSP services.


**Special?**
- Better RTSP Handling: Rather than relying on external libraries or raw socket guessing, Diana actively probes RTSP responses, parses realm, nonce, and qop data, and constructs valid MD5 Digest hashes on the fly.
- Dynamic Web Form Detection: Instead of just checking for HTTP 401 Unauthorized responses, it parses HTTP 200 OK login pages to identify dynamic <input> fields (e.g., username, pwd) to test credentials against custom web interfaces.
- All-in-One Execution: Combines host discovery, port scanning, directory fuzzing, and credential auditing into a single, cohesive terminal flow without requiring complex command-line flags.

**Requirements**
This tool relies primarily on standard libraries, minimizing dependency bloat.

Dependencies:
- Python 3.12 (Developed and tested on this version)
- requests (pip install requests)

The developer assumes no liability and is not responsible for any misuse, damage, or legal consequences caused by utilizing this tool :D
