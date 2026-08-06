import socket
import sys
from datetime import datetime

def scan_port(target_ip, port):
    """Ek single port check karta hai ki open hai ya nahi"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def scan_common_ports(target_ip):
    """Top common ports ko scan karta hai"""
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        8080: "HTTP-Proxy"
    }
    
    print(f"\n[*] Scanning target: {target_ip}")
    print(f"[*] Scan started at: {datetime.now()}\n")
    
    open_ports = []
    
    for port, service in common_ports.items():
        if scan_port(target_ip, port):
            print(f"[+] Port {port} OPEN  --> {service}")
            open_ports.append((port, service))
        else:
            print(f"[-] Port {port} closed")
    
    print(f"\n[*] Scan completed. {len(open_ports)} open ports found.")
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <target_ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_common_ports(target)