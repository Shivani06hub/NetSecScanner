import socket

def grab_banner(target_ip, port):
    """Open port se service banner grab karta hai"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_ip, port))
        
        # Kuch services (jaise HTTP) request bhejne pe hi banner dete hain
        if port == 80 or port == 8080:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        return banner if banner else "No banner received"
    except socket.error:
        return "Could not grab banner"
    except Exception as e:
        return f"Error: {str(e)}"


def nmap_service_scan(target_ip):
    """Nmap library se detailed service/version detection karta hai"""
    import nmap
    
    scanner = nmap.PortScanner()
    print(f"\n[*] Running Nmap service detection on {target_ip}...")
    print("[*] Ye thoda time le sakta hai...\n")
    
    try:
        scanner.scan(target_ip, arguments='-sV --top-ports 20')
        
        results = []
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    service_info = scanner[host][proto][port]
                    state = service_info['state']
                    name = service_info.get('name', 'unknown')
                    product = service_info.get('product', '')
                    version = service_info.get('version', '')
                    
                    if state == 'open':
                        print(f"[+] Port {port}/{proto} - {name} {product} {version}")
                        results.append({
                            'port': port,
                            'service': name,
                            'product': product,
                            'version': version
                        })
        return results
    except Exception as e:
        print(f"[-] Nmap scan error: {str(e)}")
        return []