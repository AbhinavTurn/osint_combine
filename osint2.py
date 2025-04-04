#!/usr/bin/env python3
import argparse
import socket
import requests
import whois
import dns.resolver
import json
import subprocess
import re
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

# Initialize colorama
init()

class OsintTool:
    def __init__(self):
        self.target = None
        self.output = {}
        
    def banner(self):
        print(f"""{Fore.CYAN}
╔═══════════════════════════════════════════════╗
║                                               ║
║   ██████╗ ███████╗██╗███╗   ██╗████████╗      ║
║  ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝      ║
║  ██║   ██║███████╗██║██╔██╗ ██║   ██║         ║
║  ██║   ██║╚════██║██║██║╚██╗██║   ██║         ║
║  ╚██████╔╝███████║██║██║ ╚████║   ██║         ║
║   ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝         ║
║                                               ║
║            Reconnaissance Tool                ║
╚═══════════════════════════════════════════════╝
{Style.RESET_ALL}""")

    def set_target(self, target):
        """Set the target domain or IP address"""
        self.target = target
        self.output = {"target": target, "results": {}}
        
    def is_ip_address(self, target):
        """Check if the target is an IP address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(pattern, target))
    
    def get_ip(self):
        """Get IP address from domain name"""
        if self.is_ip_address(self.target):
            return self.target
        
        try:
            ip = socket.gethostbyname(self.target)
            self.output["results"]["ip_address"] = ip
            print(f"{Fore.GREEN}[+] IP Address: {ip}{Style.RESET_ALL}")
            return ip
        except socket.gaierror:
            print(f"{Fore.RED}[-] Could not resolve hostname{Style.RESET_ALL}")
            self.output["results"]["ip_address"] = "Not found"
            return None
    
    def get_whois(self):
        """Get WHOIS information"""
        try:
            whois_info = whois.whois(self.target)
            simplified_whois = {
                "registrar": whois_info.registrar,
                "creation_date": str(whois_info.creation_date),
                "expiration_date": str(whois_info.expiration_date),
                "name_servers": whois_info.name_servers if isinstance(whois_info.name_servers, list) else [whois_info.name_servers],
                "emails": whois_info.emails if isinstance(whois_info.emails, list) else [whois_info.emails] if whois_info.emails else []
            }
            self.output["results"]["whois"] = simplified_whois
            print(f"{Fore.GREEN}[+] WHOIS Information:{Style.RESET_ALL}")
            print(f"  Registrar: {simplified_whois['registrar']}")
            print(f"  Creation Date: {simplified_whois['creation_date']}")
            print(f"  Expiration Date: {simplified_whois['expiration_date']}")
            print(f"  Name Servers: {', '.join(filter(None, simplified_whois['name_servers']))}")
            if simplified_whois['emails']:
                print(f"  Contact Emails: {', '.join(filter(None, simplified_whois['emails']))}")
        except Exception as e:
            print(f"{Fore.RED}[-] WHOIS lookup failed: {e}{Style.RESET_ALL}")
            self.output["results"]["whois"] = "Lookup failed"
    
    def get_dns_records(self):
        """Get various DNS records"""
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        dns_results = {}
        
        if self.is_ip_address(self.target):
            print(f"{Fore.YELLOW}[!] DNS lookup skipped for IP address{Style.RESET_ALL}")
            self.output["results"]["dns_records"] = "Skipped for IP address"
            return
        
        print(f"{Fore.GREEN}[+] DNS Records:{Style.RESET_ALL}")
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = [str(rdata) for rdata in answers]
                dns_results[record_type] = records
                print(f"  {record_type} Records: {', '.join(records)}")
            except Exception:
                pass
        
        self.output["results"]["dns_records"] = dns_results
    
    def scan_common_ports(self, ip):
        """Scan common ports"""
        if not ip:
            self.output["results"]["port_scan"] = "Skipped due to DNS resolution failure"
            return
            
        common_ports = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 
                        1433, 3306, 3389, 5060, 5900, 8080, 8443]
        open_ports = {}
        
        print(f"{Fore.GREEN}[+] Port Scan Results:{Style.RESET_ALL}")
        
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port, result == 0
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(lambda p: check_port(p), common_ports))
            
        for port, is_open in results:
            if is_open:
                service = socket.getservbyport(port) if port in socket.getservbyport_tcp() else "unknown"
                open_ports[port] = service
                print(f"  Port {port}: {Fore.GREEN}Open{Style.RESET_ALL} ({service})")
        
        if not open_ports:
            print(f"  {Fore.YELLOW}No open ports found among commonly scanned ports{Style.RESET_ALL}")
            
        self.output["results"]["port_scan"] = open_ports
    
    def get_http_headers(self):
        """Get HTTP headers from the web server"""
        protocols = ["https", "http"]
        headers_found = False
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{self.target}"
                response = requests.get(url, timeout=5)
                headers = dict(response.headers)
                
                print(f"{Fore.GREEN}[+] HTTP Headers ({protocol}):{Style.RESET_ALL}")
                for header, value in headers.items():
                    print(f"  {header}: {value}")
                
                self.output["results"][f"{protocol}_headers"] = headers
                headers_found = True
                
                # Check for security headers
                security_headers = {
                    "Strict-Transport-Security": "HSTS not set",
                    "Content-Security-Policy": "CSP not set",
                    "X-Content-Type-Options": "Not set",
                    "X-Frame-Options": "Not set",
                    "X-XSS-Protection": "Not set"
                }
                
                for header in security_headers:
                    if header in headers:
                        security_headers[header] = headers[header]
                
                self.output["results"]["security_headers"] = security_headers
                
                # Try to determine web technologies
                tech_markers = {
                    "WordPress": ["wp-content", "wp-includes"],
                    "Joomla": ["com_content", "com_users"],
                    "Drupal": ["Drupal", "drupal"],
                    "Bootstrap": ["bootstrap"],
                    "jQuery": ["jquery"],
                    "React": ["react"],
                    "Angular": ["ng-", "angular"],
                    "ASP.NET": [".aspx", "__VIEWSTATE"],
                    "PHP": ["X-Powered-By: PHP"],
                    "Apache": ["Apache"],
                    "Nginx": ["nginx"],
                    "IIS": ["IIS"]
                }
                
                technologies = []
                html_content = response.text.lower()
                
                for tech, markers in tech_markers.items():
                    for marker in markers:
                        if marker.lower() in html_content or any(marker.lower() in str(v).lower() for v in headers.values()):
                            technologies.append(tech)
                            break
                
                if technologies:
                    self.output["results"]["technologies"] = technologies
                    print(f"{Fore.GREEN}[+] Detected Technologies: {', '.join(technologies)}{Style.RESET_ALL}")
                
                # Break after the first successful protocol
                break
            
            except Exception as e:
                pass
        
        if not headers_found:
            print(f"{Fore.RED}[-] Failed to retrieve HTTP headers{Style.RESET_ALL}")
            self.output["results"]["http_headers"] = "Failed to retrieve"
    
    def save_results(self, filename=None):
        """Save results to a JSON file"""
        if not filename:
            filename = f"{self.target}_recon.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.output, f, indent=4)
            print(f"{Fore.GREEN}[+] Results saved to {filename}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to save results: {e}{Style.RESET_ALL}")
            return False
    
    def run_recon(self):
        """Run all reconnaissance methods"""
        print(f"{Fore.CYAN}[*] Starting reconnaissance on {self.target}{Style.RESET_ALL}")
        
        ip = self.get_ip()
        self.get_whois()
        self.get_dns_records()
        self.scan_common_ports(ip)
        self.get_http_headers()
        
        print(f"{Fore.CYAN}[*] Reconnaissance completed for {self.target}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="Basic OSINT Reconnaissance Tool")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("-o", "--output", help="Output file name")
    args = parser.parse_args()
    
    tool = OsintTool()
    tool.banner()
    tool.set_target(args.target)
    tool.run_recon()
    
    if args.output:
        tool.save_results(args.output)
    else:
        tool.save_results()


if __name__ == "__main__":
    main()
