import requests

def check_security_headers(url):
    """Website ke HTTP security headers check karta hai"""
    
    # Agar http:// ya https:// missing hai to add kar do
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    
    important_headers = {
        'Strict-Transport-Security': 'HSTS - forces HTTPS connections',
        'Content-Security-Policy': 'CSP - prevents XSS attacks',
        'X-Frame-Options': 'Prevents clickjacking attacks',
        'X-Content-Type-Options': 'Prevents MIME-sniffing attacks',
        'Referrer-Policy': 'Controls referrer information leakage',
        'Permissions-Policy': 'Controls browser feature permissions'
    }
    
    print(f"\n[*] Checking security headers for: {url}\n")
    
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        results = {'present': [], 'missing': []}
        
        for header, description in important_headers.items():
            if header in headers:
                print(f"[+] {header}: PRESENT")
                print(f"    Value: {headers[header]}")
                results['present'].append(header)
            else:
                print(f"[-] {header}: MISSING")
                print(f"    Risk: {description}")
                results['missing'].append(header)
            print()
        
        # Server info bhi check karo (version disclosure risk)
        if 'Server' in headers:
            print(f"[!] Server header exposed: {headers['Server']}")
            print("    Risk: Version disclosure - attacker ko exact server software pata chal sakta hai\n")
        
        print(f"[*] Summary: {len(results['present'])} present, {len(results['missing'])} missing")
        
        return results
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Error connecting to {url}: {str(e)}")
        return None