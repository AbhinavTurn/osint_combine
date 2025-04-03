#!/usr/bin/env python3
import requests
import socket
import json
import re
import whois
import dns.resolver
from selenium import webdriver
from concurrent.futures import ThreadPoolExecutor

# API Keys (Replace with your own)
SHODAN_API_KEY = "your_shodan_api_key_here"
HIBP_API_KEY = "your_hibp_api_key_here"

class OSINTTool:
    def __init__(self, target):
        self.target = target
        self.results = {"Target": target}
    
    def is_ip_address(self, target):
        """Check if the target is an IP address."""
        return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target))
    
    def get_ip(self):
        """Resolve IP address from domain."""
        if self.is_ip_address(self.target):
            self.results["IP Address"] = self.target
            return self.target
        try:
            ip = socket.gethostbyname(self.target)
            self.results["IP Address"] = ip
            return ip
        except:
            self.results["IP Address"] = "Not found"
            return None
    
    def get_whois_info(self):
        """Fetch WHOIS information."""
        try:
            w = whois.whois(self.target)
            self.results["WHOIS"] = {
                "Registrar": w.registrar,
                "Creation Date": str(w.creation_date),
                "Expiration Date": str(w.expiration_date),
                "Name Servers": w.name_servers,
                "Emails": w.emails
            }
        except Exception as e:
            self.results["WHOIS"] = f"Error: {e}"
    
    def get_dns_records(self):
        """Retrieve DNS records."""
        dns_records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        for record in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record)
                dns_records[record] = [str(r) for r in answers]
            except:
                pass
        self.results["DNS Records"] = dns_records
    
    def get_subdomains(self):
        """Fetch subdomains from crt.sh."""
        url = f"https://crt.sh/?q={self.target}&output=json"
        try:
            response = requests.get(url, timeout=10)
            data = response.json()
            subdomains = sorted(set(entry['name_value'] for entry in data))
            self.results["Subdomains"] = subdomains
        except:
            self.results["Subdomains"] = "Failed to fetch"
    
    def reverse_ip_lookup(self):
        """Find other domains on the same server."""
        url = f"https://api.hackertarget.com/reverseiplookup/?q={self.get_ip()}"
        try:
            response = requests.get(url, timeout=10)
            self.results["Reverse IP"] = response.text.split("\n")
        except:
            self.results["Reverse IP"] = "Failed to fetch"
    
    def shodan_lookup(self):
        """Fetch Shodan data."""
        ip = self.get_ip()
        if not ip:
            return
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        try:
            response = requests.get(url, timeout=10)
            self.results["Shodan Info"] = response.json()
        except:
            self.results["Shodan Info"] = "Failed to fetch"
    
    def extract_emails(self):
        """Extract emails from website source code."""
        url = f"https://{self.target}"
        try:
            response = requests.get(url, timeout=10)
            emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", response.text))
            self.results["Emails Found"] = list(emails)
        except:
            self.results["Emails Found"] = "Failed to fetch"
    
    def check_pwned_emails(self):
        """Check if emails have been in data breaches."""
        if "Emails Found" not in self.results or not self.results["Emails Found"]:
            return
        breached_accounts = {}
        headers = {"hibp-api-key": HIBP_API_KEY}
        for email in self.results["Emails Found"]:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    breached_accounts[email] = response.json()
            except:
                breached_accounts[email] = "No breaches found"
        self.results["Pwned Emails"] = breached_accounts
    
    def google_dork_social(self):
        """Generate Google Dorking queries for social media OSINT."""
        queries = [
            f'site:twitter.com "{self.target}"',
            f'site:linkedin.com "{self.target}"',
            f'site:github.com "{self.target}"'
        ]
        self.results["Social Media Dorks"] = queries
    
    def check_dark_web(self):
        """Search target on dark web."""
        tor_url = f"http://onion.link/search?q={self.target}"
        try:
            response = requests.get(tor_url, timeout=10, proxies={'http': 'socks5h://127.0.0.1:9050'})
            self.results["Dark Web Mentions"] = response.text[:500]
        except:
            self.results["Dark Web Mentions"] = "Failed to fetch"
    
    def take_screenshot(self):
        """Capture website screenshot."""
        try:
            options = webdriver.ChromeOptions()
            options.add_argument("--headless")
            driver = webdriver.Chrome(options=options)
            driver.get(f"https://{self.target}")
            driver.save_screenshot(f"{self.target}.png")
            driver.quit()
            self.results["Screenshot"] = f"{self.target}.png"
        except:
            self.results["Screenshot"] = "Failed to capture"
    
    def run_all(self):
        """Run all OSINT tasks in parallel."""
        with ThreadPoolExecutor() as executor:
            executor.submit(self.get_ip)
            executor.submit(self.get_whois_info)
            executor.submit(self.get_dns_records)
            executor.submit(self.get_subdomains)
            executor.submit(self.reverse_ip_lookup)
            executor.submit(self.shodan_lookup)
            executor.submit(self.extract_emails)
            executor.submit(self.check_pwned_emails)
            executor.submit(self.google_dork_social)
            executor.submit(self.check_dark_web)
            executor.submit(self.take_screenshot)
    
    def save_results(self):
        """Save results to a JSON file."""
        with open(f"{self.target}_osint_results.json", "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"Results saved to {self.target}_osint_results.json")

if __name__ == "__main__":
    target = input("Enter target (domain/IP): ").strip()
    tool = OSINTTool(target)
    tool.run_all()
    tool.save_results()
